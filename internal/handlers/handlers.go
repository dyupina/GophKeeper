package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"gophkeeper/internal/config"
	"gophkeeper/internal/models"
	"gophkeeper/internal/storage"
	"gophkeeper/internal/user"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// contextKey is a custom type.
type contextKey string

// UserIDKey is a "User-ID".
const UserIDKey contextKey = "User-ID"

type Controller struct {
	conf           *config.Config
	storageService storage.StorageService
	logger         *zap.SugaredLogger
	userService    user.UserService
}

// NewController creates and returns a new instance of Controller using the provided configuration,
// storage, logger, and user service components.
func NewController(conf *config.Config, storageService storage.StorageService, logger *zap.SugaredLogger, userService user.UserService) *Controller {
	con := &Controller{
		conf:           conf,
		storageService: storageService,
		logger:         logger,
		userService:    userService,
	}

	return con
}

// HandleGracefulShutdown handles termination signals.
func (con *Controller) HandleGracefulShutdown(server *http.Server) {
	notifyCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	// Ждем получения первого сигнала
	<-notifyCtx.Done()
	con.logger.Infof("Received shutdown signal")

	// Отключаем прием новых подключений и дожидаемся завершения активных запросов
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(con.conf.Timeout)*time.Second)
	defer cancel()

	// Закрываем соединение с базой данных.
	go func() {
		if con.conf.DBConnection != "" {
			con.logger.Infof("Closing database connection...")
			if err := con.storageService.Close(); err != nil {
				con.logger.Errorf("Failed to close database connection: %v", err)
			}
		}
	}()

	con.logger.Infof("Shutting down gracefully...")
	if err := server.Shutdown(ctx); err != nil {
		con.logger.Infof("HTTP server shutdown error: %v", err)
	}

	con.logger.Infof("Server has been shut down.")
}

func (con *Controller) handleAuth(res http.ResponseWriter, userID string, user_ user.User) {
	storedHashedPassword := con.storageService.GetHashedPasswordByLogin(user_.Login)
	if storedHashedPassword == "" || !con.storageService.CheckPasswordHash(user_.Password, storedHashedPassword) {
		con.Debug(res, "Unauthorized: Invalid login/password", http.StatusUnauthorized)
		return
	}

	err := con.storageService.SaveUID(userID, user_.Login)
	if err != nil {
		con.Debug(res, "Bad request", http.StatusBadRequest)
		return
	}

	// Проверяем, есть ли уже активный токен для пользователя
	existingToken, err := con.storageService.GetTokenByUserID(userID)
	if err == nil && existingToken != "" {
		// Возвращаем существующий токен
		res.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(res).Encode(map[string]string{"token": existingToken}); err != nil {
			http.Error(res, "Failed to encode token", http.StatusInternalServerError)
			return
		}
		con.Debug(res, "Auth success (existing token)", http.StatusOK)
		return
	}

	// Генерируем новый JWT
	token, err := user.GenerateToken(userID)
	if err != nil {
		http.Error(res, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Сохраняем новый токен
	err = con.storageService.SaveToken(userID, token)
	if err != nil {
		fmt.Printf("err %s\n", err)
		http.Error(res, "Failed to save token", http.StatusInternalServerError)
		return
	}

	// Возвращаем токен клиенту
	res.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(res).Encode(map[string]string{"token": token}); err != nil {
		http.Error(res, "Failed to encode token", http.StatusInternalServerError)
		return
	}

	con.Debug(res, "Auth success", http.StatusOK)
}

// Register handles the registration of a new user.
//
// Request Body:
// - A JSON object containing the fields "Login" (string) and "Password" (string).
//
// Response:
// - 200 OK: Authentication initiated successfully.
// - 400 Bad Request: Invalid or missing login/password in the request body.
// - 409 Conflict: The provided login is already taken.
// - 500 Internal Server Error: An error occurred during password hashing or storage.
func (con *Controller) Register() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := uuid.New().String()

		var user_ user.User
		err := json.NewDecoder(req.Body).Decode(&user_)
		login := user_.Login
		password := user_.Password
		if err != nil || login == "" || password == "" {
			con.Debug(res, "Bad request", http.StatusBadRequest)
			return
		}

		hashedPassword, err := con.storageService.HashPassword(password)
		if err != nil {
			con.Debug(res, "(Register) Internal server error", http.StatusInternalServerError)
			return
		}

		ok := con.storageService.SaveLoginPassword(login, hashedPassword)
		if !ok {
			con.Debug(res, "Conflict: Login already taken", http.StatusConflict)
			return
		}

		con.handleAuth(res, userID, user_)
	}
}

// Login handles user authentication by verifying the provided login and password.
//
// Request Body:
// - A JSON object containing the fields "Login" (string) and "Password" (string).
//
// Response:
// - 200 OK: Authentication initiated successfully.
// - 400 Bad Request: Invalid or missing login/password in the request body.
// - 401 Unauthorized: Invalid login or password.
func (con *Controller) Login() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var user_ user.User
		err := json.NewDecoder(req.Body).Decode(&user_)
		if err != nil || user_.Login == "" || user_.Password == "" {
			con.Debug(res, "Bad request", http.StatusBadRequest)
			return
		}

		userID, err := con.storageService.GetUserIDByLogin(user_.Login)
		if err != nil {
			con.Debug(res, "Unauthorized: Invalid login/password", http.StatusUnauthorized)
			return
		}

		con.handleAuth(res, userID, user_)
	}
}

// PanicRecoveryMiddleware recovers the application after a panic.
func (con *Controller) PanicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				con.logger.Errorf("Error recovering from panic: %v", err)
				http.Error(res, "Error recovering from panic", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(res, req)
	})
}

// AuthenticateMiddleware validates the JWT and adds the user ID to the context.
func (con *Controller) AuthenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Список открытых эндпоинтов
		openEndpoints := map[string]bool{
			"/register": true,
			"/login":    true,
			"/ping":     true,
		}

		// Если эндпоинт открыт, пропускаем запрос
		if openEndpoints[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Unauthorized: Invalid token format", http.StatusUnauthorized)
			return
		}

		claims, err := user.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (con *Controller) Debug(res http.ResponseWriter, formatString string, code int) {
	con.logger.Debugf(formatString)
	if code != http.StatusOK {
		http.Error(res, formatString, code)
	} else {
		// _, _ = res.Write([]byte(formatString + "\n"))
		res.WriteHeader(http.StatusOK)
	}
}

// SavePrivateData handles the saving of private data for a user.
//
// Request Body:
// - A JSON object containing the fields:
//   - "Key" (string): The key for the private data entry.
//   - "Value" (string): The value associated with the key.
//   - "DataType" (string): The type of data being stored.
//   - "Metadata" (string): Optional metadata associated with the data.
//
// Response:
// - 200 OK: Private data saved successfully.
// - 400 Bad Request: Invalid or missing fields in the request body.
// - 500 Internal Server Error: An error occurred while saving the data.
func (con *Controller) SavePrivateData() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := req.Context().Value(UserIDKey).(string)

		err := json.NewDecoder(req.Body).Decode(&models.PrivateDataResp)
		if err != nil || models.PrivateDataResp.Key == "" || models.PrivateDataResp.Value == "" || models.PrivateDataResp.DataType == "" {
			con.Debug(res, "Bad request", http.StatusBadRequest)
			return
		}
		err = con.storageService.SavePrivateData(userID, models.PrivateDataResp.Key, models.PrivateDataResp.Value, models.PrivateDataResp.DataType, models.PrivateDataResp.Metadata)

		if err != nil {
			con.Debug(res, "Internal server error", http.StatusInternalServerError)
			return
		}

		con.Debug(res, "Save success", http.StatusOK)
	}
}

// GetPrivateData retrieves private data for a user based on the provided key.
//
// Request Body:
// - A JSON object containing the field:
//   - "Key" (string): The key for the private data entry to retrieve.
//
// Response:
// - 200 OK: Private data retrieved successfully. Returns a JSON object with:
//   - "value": The stored value.
//   - "data_type": The type of the stored data.
//   - "metadata": Optional metadata associated with the data.
//
// - 400 Bad Request: Invalid or missing key in the request body.
// - 404 Not Found: No data found for the provided key.
// - 500 Internal Server Error: An error occurred while retrieving the data.
func (con *Controller) GetPrivateData() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := req.Context().Value(UserIDKey).(string)

		err := json.NewDecoder(req.Body).Decode(&models.PrivateDataReq)
		if err != nil || models.PrivateDataReq.Key == "" {
			con.Debug(res, "Bad request", http.StatusBadRequest)
			return
		}

		value, dataType, metadata, err := con.storageService.GetPrivateData(userID, models.PrivateDataReq.Key)
		if err != nil {
			con.Debug(res, "Internal server error", http.StatusInternalServerError)
			return
		}
		if value == "" {
			con.Debug(res, "Not found", http.StatusNotFound)
			return
		}

		res.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(res).Encode(map[string]interface{}{
			"value":     value,
			"data_type": dataType,
			"metadata":  metadata,
		})

		if err != nil {
			http.Error(res, "Failed to encode", http.StatusInternalServerError)
			return
		}

		con.Debug(res, "Get success", http.StatusOK)
	}
}

// DeletePrivateData handles the deletion of private data for a user based on the provided key.
//
// Request Body:
// - A JSON object containing the field:
//   - "Key" (string): The key for the private data entry to delete.
//
// Response:
// - 200 OK: Data deleted successfully.
// - 400 Bad Request: Invalid or missing key in the request body.
// - 500 Internal Server Error: An error occurred while deleting the data or no data found for deletion.
func (con *Controller) DeletePrivateData() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := req.Context().Value(UserIDKey).(string)

		err := json.NewDecoder(req.Body).Decode(&models.PrivateDataReq)
		if err != nil || models.PrivateDataReq.Key == "" {
			http.Error(res, "Invalid request body", http.StatusBadRequest)
			return
		}

		rowsDeleted, err := con.storageService.DeletePrivateData(userID, models.PrivateDataReq.Key)
		if err != nil {
			con.Debug(res, "Internal server error", http.StatusInternalServerError)
			return
		}
		if rowsDeleted == 0 {
			con.Debug(res, "No data found for deletion", http.StatusInternalServerError)
			return
		}

		con.Debug(res, "Data deleted successfully", http.StatusOK)
	}
}

// ListPrivateData retrieves a list of all private data entries for a user.
//
// Response:
// - 200 OK: Returns a JSON array of private data entries.
// - 500 Internal Server Error: An error occurred while fetching the data.
func (con *Controller) ListPrivateData() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		userID := req.Context().Value(UserIDKey).(string)

		dataList, err := con.storageService.ListPrivateData(userID)
		if err != nil {
			con.Debug(res, "Internal server error", http.StatusInternalServerError)
			return
		}

		res.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(res).Encode(dataList)
		if err != nil {
			http.Error(res, "Failed to encode", http.StatusInternalServerError)
			return
		}
	}
}

// Ping checks the health of the server and the database connection.
//
// Response:
// - 200 OK: The server and database are healthy.
// - 500 Internal Server Error: MASTER_KEY_ROTATION is in progress or a database connection error occurred.
func (con *Controller) Ping() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		if storage.MASTER_KEY_ROTATION {
			con.Debug(res, "MASTER_KEY_ROTATION", http.StatusInternalServerError)
			return
		}

		err := con.storageService.PingHandler()
		if err != nil {
			con.logger.Errorf("Database connection error: %v", err)
			http.Error(res, "Database connection error", http.StatusInternalServerError)
			return
		}

		res.WriteHeader(http.StatusOK)
	}
}
