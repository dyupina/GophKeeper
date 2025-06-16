package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gophkeeper/internal/config"
	"gophkeeper/internal/logger"
	"gophkeeper/internal/mocks"
	"gophkeeper/internal/storage"
	"gophkeeper/internal/user"
	"os"
	"os/signal"
	"syscall"
	"time"

	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestConfigInit(t *testing.T) {
	cfg := config.NewConfig()
	err := config.Init(cfg)
	assert.NoError(t, err)
	// assert.NotEmpty(t, cfg.Addr)
}

func TestRegister_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		input              user.User
		mockHashPassword   func()
		mockSaveLoginPass  func()
		expectedStatusCode int
	}{
		{
			name: "Success",
			input: user.User{
				Login:    "testuser",
				Password: "password123",
			},
			mockHashPassword: func() {
				mockStorage.EXPECT().HashPassword("password123").Return("hashed_password", nil)
			},
			mockSaveLoginPass: func() {
				mockStorage.EXPECT().SaveLoginPassword("testuser", "hashed_password").Return(true)
				mockStorage.EXPECT().GetHashedPasswordByLogin("testuser").Return("hashed_password")
				mockStorage.EXPECT().CheckPasswordHash("password123", "hashed_password").Return(true)
				mockStorage.EXPECT().SaveUID(gomock.Any(), "testuser").Return(nil)
				mockStorage.EXPECT().GetTokenByUserID(gomock.Any()).Return("", errors.New("not found"))
				mockStorage.EXPECT().SaveToken(gomock.Any(), gomock.Any()).Return(nil)
				mockStorage.EXPECT().Close().AnyTimes()
				mockStorage.EXPECT().MasterKeyRotation().AnyTimes()
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "BadRequest_EmptyBody",
			input: user.User{
				Login:    "",
				Password: "",
			},
			mockHashPassword:   func() {},
			mockSaveLoginPass:  func() {},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "BadRequest_InvalidJSON",
			input:              user.User{},
			mockHashPassword:   func() {},
			mockSaveLoginPass:  func() {},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "InternalServerError_HashError",
			input: user.User{
				Login:    "testuser",
				Password: "password123",
			},
			mockHashPassword: func() {
				mockStorage.EXPECT().HashPassword("password123").Return("", errors.New("hash error"))
			},
			mockSaveLoginPass:  func() {},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name: "Conflict_LoginTaken",
			input: user.User{
				Login:    "testuser",
				Password: "password123",
			},
			mockHashPassword: func() {
				mockStorage.EXPECT().HashPassword("password123").Return("hashed_password", nil)
			},
			mockSaveLoginPass: func() {
				mockStorage.EXPECT().SaveLoginPassword("testuser", "hashed_password").Return(false)
			},
			expectedStatusCode: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.name == "BadRequest_InvalidJSON" {
				body = []byte("invalid-json")
			} else if tt.name != "BadRequest_EmptyBody" {
				body, _ = json.Marshal(tt.input)
			}

			req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
			res := httptest.NewRecorder()

			tt.mockHashPassword()
			tt.mockSaveLoginPass()

			controller.Register()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)
		})
	}
}

func TestLogin_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		input              user.User
		mockGetUserID      func()
		mockHandleAuth     func()
		expectedStatusCode int
	}{
		{
			name: "Success",
			input: user.User{
				Login:    "testuser",
				Password: "password123",
			},
			mockGetUserID: func() {
				mockStorage.EXPECT().GetUserIDByLogin("testuser").Return("user-123", nil)
			},
			mockHandleAuth: func() {
				mockStorage.EXPECT().GetHashedPasswordByLogin("testuser").Return("hashed_password")
				mockStorage.EXPECT().CheckPasswordHash("password123", "hashed_password").Return(true)
				mockStorage.EXPECT().SaveUID("user-123", "testuser").Return(nil)
				mockStorage.EXPECT().GetTokenByUserID("user-123").Return("", errors.New("not found"))
				mockStorage.EXPECT().SaveToken("user-123", gomock.Any()).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "BadRequest_EmptyBody",
			input: user.User{
				Login:    "",
				Password: "",
			},
			mockGetUserID:      func() {},
			mockHandleAuth:     func() {},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:               "BadRequest_InvalidJSON",
			input:              user.User{},
			mockGetUserID:      func() {},
			mockHandleAuth:     func() {},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name: "Unauthorized_UserNotFound",
			input: user.User{
				Login:    "unknown",
				Password: "pass",
			},
			mockGetUserID: func() {
				mockStorage.EXPECT().GetUserIDByLogin("unknown").Return("", errors.New("user not found"))
			},
			mockHandleAuth:     func() {},
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name: "Unauthorized_StorageError",
			input: user.User{
				Login:    "testuser",
				Password: "pass",
			},
			mockGetUserID: func() {
				mockStorage.EXPECT().GetUserIDByLogin("testuser").Return("", errors.New("db error"))
			},
			mockHandleAuth:     func() {},
			expectedStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.name == "BadRequest_InvalidJSON" {
				body = []byte("invalid-json")
			} else if tt.name != "BadRequest_EmptyBody" {
				body, _ = json.Marshal(tt.input)
			}

			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
			res := httptest.NewRecorder()

			tt.mockGetUserID()
			tt.mockHandleAuth()

			controller.Login()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)
		})
	}
}

func TestSavePrivateData_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		userID             string
		input              map[string]string // key, value, data_type, metadata
		mockSavePrivate    func(userID, key, value, dataType, metadata string) error
		expectedStatusCode int
	}{
		{
			name:   "Success",
			userID: "user-123",
			input: map[string]string{
				"key":       "my_key",
				"value":     "my_value",
				"data_type": "text",
				"metadata":  "optional_info",
			},
			mockSavePrivate: func(userID, key, value, dataType, metadata string) error {
				mockStorage.EXPECT().SavePrivateData(userID, key, value, dataType, metadata).Return(nil)
				return nil
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:   "Success_Without_Metadata",
			userID: "user-123",
			input: map[string]string{
				"key":       "my_key",
				"value":     "my_value",
				"data_type": "text",
			},
			mockSavePrivate: func(userID, key, value, dataType, metadata string) error {
				mockStorage.EXPECT().SavePrivateData(userID, key, value, dataType, "").Return(nil)
				return nil
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:   "BadRequest_EmptyBody",
			userID: "user-123",
			input:  map[string]string{},
			mockSavePrivate: func(userID, key, value, dataType, metadata string) error {
				return nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "BadRequest_MissingFields",
			userID: "user-123",
			input: map[string]string{
				"key":       "",
				"value":     "my_value",
				"data_type": "",
			},
			mockSavePrivate: func(userID, key, value, dataType, metadata string) error {
				return nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "InternalServerError_SaveError",
			userID: "user-123",
			input: map[string]string{
				"key":       "my_key",
				"value":     "my_value",
				"data_type": "text",
			},
			mockSavePrivate: func(userID, key, value, dataType, metadata string) error {
				mockStorage.EXPECT().SavePrivateData(userID, key, value, dataType, "").Return(errors.New("save failed"))
				return nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyJSON, _ := json.Marshal(map[string]string{
				"key":       tt.input["key"],
				"value":     tt.input["value"],
				"data_type": tt.input["data_type"],
				"metadata":  tt.input["metadata"],
			})
			req, _ := http.NewRequest("POST", "/save", bytes.NewBuffer(bodyJSON))

			ctx := req.Context()
			ctx = context.WithValue(ctx, UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			res := httptest.NewRecorder()

			if tt.mockSavePrivate != nil {
				_ = tt.mockSavePrivate(tt.userID, tt.input["key"], tt.input["value"], tt.input["data_type"], tt.input["metadata"])
			}

			controller.SavePrivateData()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)
		})
	}
}

func TestGetPrivateData_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		userID             string
		input              map[string]string // key
		mockGetPrivate     func(userID, key string) (string, string, string, error)
		expectedStatusCode int
		expectedResponse   map[string]interface{}
	}{
		{
			name:   "Success",
			userID: "user-123",
			input: map[string]string{
				"key": "my_key",
			},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				mockStorage.EXPECT().GetPrivateData(userID, key).Return("my_value", "text", "optional_metadata", nil)
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse: map[string]interface{}{
				"value":     "my_value",
				"data_type": "text",
				"metadata":  "optional_metadata",
			},
		},
		{
			name:   "Success_Without_Metadata",
			userID: "user-123",
			input: map[string]string{
				"key": "my_key",
			},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				mockStorage.EXPECT().GetPrivateData(userID, key).Return("my_value", "text", "", nil)
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse: map[string]interface{}{
				"value":     "my_value",
				"data_type": "text",
				"metadata":  "",
			},
		},
		{
			name:   "BadRequest_EmptyBody",
			userID: "user-123",
			input:  map[string]string{},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "BadRequest_MissingKey",
			userID: "user-123",
			input: map[string]string{
				"key": "",
			},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "NotFound_NoValue",
			userID: "user-123",
			input: map[string]string{
				"key": "unknown_key",
			},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				mockStorage.EXPECT().GetPrivateData(userID, key).Return("", "", "", nil)
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:   "InternalServerError_GetError",
			userID: "user-123",
			input: map[string]string{
				"key": "my_key",
			},
			mockGetPrivate: func(userID, key string) (string, string, string, error) {
				mockStorage.EXPECT().GetPrivateData(userID, key).Return("", "", "", errors.New("db error"))
				return "", "", "", nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyJSON, _ := json.Marshal(map[string]string{
				"key": tt.input["key"],
			})
			req, _ := http.NewRequest("POST", "/get", bytes.NewBuffer(bodyJSON))

			ctx := req.Context()
			ctx = context.WithValue(ctx, UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			res := httptest.NewRecorder()

			if tt.mockGetPrivate != nil {
				_, _, _, _ = tt.mockGetPrivate(tt.userID, tt.input["key"])
			}

			controller.GetPrivateData()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)

			if tt.expectedResponse != nil {
				var response map[string]interface{}
				err := json.Unmarshal(res.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Equal(t, tt.expectedResponse, response)
			}
		})
	}
}

func TestDeletePrivateData_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		userID             string
		input              map[string]string
		mockDelete         func(userID, key string) (int64, error)
		expectedStatusCode int
	}{
		{
			name:   "Success",
			userID: "user-123",
			input: map[string]string{
				"key": "my_key",
			},
			mockDelete: func(userID, key string) (int64, error) {
				mockStorage.EXPECT().DeletePrivateData(userID, key).Return(int64(1), nil)
				return 0, nil
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:   "BadRequest_EmptyBody",
			userID: "user-123",
			input:  map[string]string{},
			mockDelete: func(userID, key string) (int64, error) {
				return 0, nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "BadRequest_MissingKey",
			userID: "user-123",
			input: map[string]string{
				"key": "",
			},
			mockDelete: func(userID, key string) (int64, error) {
				return 0, nil
			},
			expectedStatusCode: http.StatusBadRequest,
		},
		{
			name:   "InternalServerError_DeleteError",
			userID: "user-123",
			input: map[string]string{
				"key": "my_key",
			},
			mockDelete: func(userID, key string) (int64, error) {
				mockStorage.EXPECT().DeletePrivateData(userID, key).Return(int64(0), errors.New("db error"))
				return 0, nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:   "NoDataFound",
			userID: "user-123",
			input: map[string]string{
				"key": "unknown",
			},
			mockDelete: func(userID, key string) (int64, error) {
				mockStorage.EXPECT().DeletePrivateData(userID, key).Return(int64(0), nil)
				return 0, nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyJSON, _ := json.Marshal(map[string]string{"key": tt.input["key"]})
			req, _ := http.NewRequest("POST", "/delete", bytes.NewBuffer(bodyJSON))

			ctx := req.Context()
			ctx = context.WithValue(ctx, UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			res := httptest.NewRecorder()

			if tt.mockDelete != nil {
				_, _ = tt.mockDelete(tt.userID, tt.input["key"])
			}

			controller.DeletePrivateData()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)
		})
	}
}

func TestListPrivateData_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	data := map[string]map[string]string{
		"key1": {"data_type": "text", "metadata": "meta1"},
		"key2": {"data_type": "binary", "metadata": ""},
	}

	tests := []struct {
		name               string
		userID             string
		mockList           func(userID string) (map[string]map[string]string, error)
		expectedStatusCode int
		expectedResponse   map[string]map[string]string
	}{
		{
			name:   "Success",
			userID: "user-123",
			mockList: func(userID string) (map[string]map[string]string, error) {
				mockStorage.EXPECT().ListPrivateData(userID).Return(data, nil)
				return nil, nil
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   data,
		},
		{
			name:   "InternalServerError_ListError",
			userID: "user-123",
			mockList: func(userID string) (map[string]map[string]string, error) {
				mockStorage.EXPECT().ListPrivateData(userID).Return(nil, errors.New("db error"))
				return nil, nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/list", nil)

			ctx := req.Context()
			ctx = context.WithValue(ctx, UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			res := httptest.NewRecorder()

			if tt.mockList != nil {
				_, _ = tt.mockList(tt.userID)
			}

			controller.ListPrivateData()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)

			if tt.expectedResponse != nil {
				var response map[string]map[string]string
				err := json.Unmarshal(res.Body.Bytes(), &response)
				require.NoError(t, err)
				require.Equal(t, tt.expectedResponse, response)
			}
		})
	}
}

func TestPing_Handlers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name               string
		mockMasterRotation bool
		mockPing           func() error
		expectedStatusCode int
	}{
		{
			name:               "Success",
			mockMasterRotation: false,
			mockPing: func() error {
				mockStorage.EXPECT().PingHandler().Return(nil)
				return nil
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "InternalServerError_MasterKeyRotation",
			mockMasterRotation: true,
			mockPing: func() error {
				return nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:               "InternalServerError_DbError",
			mockMasterRotation: false,
			mockPing: func() error {
				mockStorage.EXPECT().PingHandler().Return(errors.New("db connection failed"))
				return nil
			},
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ping", nil)
			res := httptest.NewRecorder()

			// Мокаем MASTER_KEY_ROTATION
			storage.MASTER_KEY_ROTATION = tt.mockMasterRotation

			if tt.mockPing != nil {
				_ = tt.mockPing()
			}

			controller.Ping()(res, req)

			require.Equal(t, tt.expectedStatusCode, res.Code)
		})
	}
}

func TestAuthenticateMiddleware(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorageService(ctrl)
	controller := &Controller{
		storageService: mockStorage,
		logger:         zap.NewNop().Sugar(),
	}

	tests := []struct {
		name       string
		token      string
		expectCode int
	}{
		{"No token", "", http.StatusUnauthorized},
		{"Invalid token", "t", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/get", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()

			authMiddleware := controller.AuthenticateMiddleware(http.DefaultServeMux)
			authMiddleware.ServeHTTP(w, req)

			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}

func TestNewController(t *testing.T) {
	ctrl := NewController(nil, nil, nil, nil)
	assert.NotNil(t, ctrl)
}

func TestHandleGracefulShutdown(t *testing.T) {
	c := gomock.NewController(t)
	defer c.Finish()

	mockStorage := mocks.NewMockStorageService(c)

	ctrl := &Controller{
		logger: nil,
		conf: &config.Config{
			Addr:         ":8085",
			DBConnection: "mock-db-connection",
			Timeout:      5,
		},
		storageService: mockStorage,
	}

	server := &http.Server{
		Addr: ":0", // случайный порт
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	// Горутина для запуска сервера
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		ctrl.HandleGracefulShutdown(server)
	}()

	// Отправляем сигнал завершения через context
	ctx, cancel := context.WithCancel(context.Background())
	signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	cancel()

	time.Sleep(100 * time.Millisecond)
}

func TestPanicRecoveryMiddleware(t *testing.T) {
	sugarLogger, _ := logger.NewLogger()
	ctrl := &Controller{
		logger: sugarLogger,
	}

	handler := ctrl.PanicRecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/ping", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, http.StatusInternalServerError, res.Code)
	assert.Contains(t, res.Body.String(), "Error recovering from panic")
}
