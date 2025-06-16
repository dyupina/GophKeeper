package storage

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"gophkeeper/internal/encryption"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
)

// StorageService defines methods for working with the data storage.
type StorageService interface {
	SaveLoginPassword(login, hashedPassword string) bool
	GetHashedPasswordByLogin(login string) string
	CheckPasswordHash(password, hash string) bool
	SaveUID(userID, login string) error
	HashPassword(password string) (string, error)
	SaveToken(userID string, token string) error
	GetTokenByUserID(userID string) (string, error)
	SavePrivateData(userID string, key string, value string, dataType string, metadata string) error
	GetPrivateData(userID string, key string) (string, string, string, error)
	DeletePrivateData(userID string, key string) (int64, error)
	ListPrivateData(userID string) (map[string]map[string]string, error)
	PingHandler() error
	MasterKeyRotation()
	GetUserIDByLogin(login string) (string, error)
	Close() error
}

var MASTER_KEY_ROTATION bool
var ErrUserNotFound = errors.New("user not found")
var ErrMKNotSet = errors.New("master key not set")

// PostgresStorage implements the StorageService interface for PostgreSQL.
type PostgresStorage struct {
	DB *sql.DB
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

// UpDBMigrations applies database migrations using the Goose library.
func UpDBMigrations(db *sql.DB) {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		log.Printf("error setting SQL dialect\n")
	}

	if err := goose.Up(db, "migrations"); err != nil {
		log.Printf("error migration %s\n", err.Error())
	}
}

// NewPostgresStorage initializes a new PostgresStorage instance.
func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("(NewPostgresStorage) failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("(NewPostgresStorage) failed to ping database: %w", err)
	}

	UpDBMigrations(db)

	return &PostgresStorage{DB: db}, nil
}

// SaveLoginPassword saves a user's login and hashed password to the database.
func (s *PostgresStorage) SaveLoginPassword(login, hashedPassword string) bool {
	_, err1 := s.DB.Exec("INSERT INTO users (login, password) VALUES ($1, $2)", login, hashedPassword)
	return err1 == nil
}

// GetHashedPasswordByLogin retrieves the hashed password for a given login from the database.
func (s *PostgresStorage) GetHashedPasswordByLogin(login string) string {
	var hashedPassword string
	_ = s.DB.QueryRow("SELECT password FROM users WHERE login=$1", login).Scan(&hashedPassword)
	return hashedPassword
}

// HashPassword generates a bcrypt hash of the given password.
func (s *PostgresStorage) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash verifies if the provided password matches the given bcrypt hash.
func (s *PostgresStorage) CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// SaveUID updates the unique identifier for a user in the database.
func (s *PostgresStorage) SaveUID(userID, login string) error {
	_, err := s.DB.Exec("UPDATE users SET uid = $1 WHERE login = $2", userID, login)
	return err
}

// SaveToken saves or updates a token for a user in the database.
func (s *PostgresStorage) SaveToken(userID string, token string) error {
	query := "INSERT INTO tokens (uid, token) VALUES ($1, $2) ON CONFLICT (uid) DO UPDATE SET token = $2"
	_, err := s.DB.Exec(query, userID, token)
	return err
}

// GetTokenByUserID retrieves the token associated with the given user ID from the database.
func (s *PostgresStorage) GetTokenByUserID(userID string) (string, error) {
	query := "SELECT token FROM tokens WHERE uid = $1"
	var token string
	err := s.DB.QueryRow(query, userID).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return token, err
}

// SavePrivateData saves or updates private data for a user in the database.
func (s *PostgresStorage) SavePrivateData(userID string, key string, value string, dataType string, metadata string) error {
	salt := make([]byte, encryption.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	masterKey := os.Getenv("MASTER_KEY")
	if masterKey == "" {
		return ErrMKNotSet
	}

	encryptionKey := encryption.GenerateKey(masterKey, salt)
	encryptedValue, err := encryption.Encrypt([]byte(value), encryptionKey)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return err
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		fmt.Printf("Err: %s\n", err)
		return err
	}

	query := `
        INSERT INTO private_data (uid, data_key, data_value, data_type, metadata, salt)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (uid, data_key) DO UPDATE SET
            data_value = $3,
            data_type = $4,
            metadata = $5,
            salt = $6
    `
	_, err = s.DB.Exec(query, userID, key, encryptedValue, dataType, metadataJSON, salt)
	return err
}

// GetPrivateData retrieves private data for a user based on the provided user ID and key.
func (s *PostgresStorage) GetPrivateData(userID string, key string) (string, string, string, error) {
	var encryptedValue, metadataJSON, salt []byte
	var dataType string

	query := `
		SELECT data_value, data_type, metadata, salt 
		FROM private_data 
		WHERE uid = $1 AND data_key = $2`

	err := s.DB.QueryRow(query, userID, key).Scan(&encryptedValue, &dataType, &metadataJSON, &salt)
	if err == sql.ErrNoRows {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", err
	}

	masterKey := os.Getenv("MASTER_KEY")
	if masterKey == "" {
		return "", "", "", ErrMKNotSet
	}

	encryptionKey := encryption.GenerateKey(masterKey, salt)
	decryptedValue, err := encryption.Decrypt(string(encryptedValue), encryptionKey)
	if err != nil {
		return "", "", "", err
	}

	var metadata string
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return "", "", "", err
	}

	return string(decryptedValue), dataType, metadata, nil
}

// DeletePrivateData deletes private data for a user based on the provided user ID and key.
func (s *PostgresStorage) DeletePrivateData(userID string, key string) (int64, error) {
	query := `DELETE FROM private_data WHERE uid = $1 AND data_key = $2`
	result, err := s.DB.Exec(query, userID, key)
	if err != nil {
		return 0, err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return 0, err
	}
	return rowsAffected, nil
}

// ListPrivateData retrieves all private data entries for a user based on the provided user ID.
func (s *PostgresStorage) ListPrivateData(userID string) (map[string]map[string]string, error) {
	query := `
		SELECT data_key, data_value, data_type, metadata, salt 
		FROM private_data 
		WHERE uid = $1`
	rows, err := s.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dataList := make(map[string]map[string]string)
	for rows.Next() {
		var key, encryptedValue, dataType string
		var metadataJSON, decryptedValue, salt []byte

		err := rows.Scan(&key, &encryptedValue, &dataType, &metadataJSON, &salt)
		if err != nil {
			return nil, err
		}

		masterKey := os.Getenv("MASTER_KEY")
		if masterKey == "" {
			return nil, ErrMKNotSet
		}

		encryptionKey := encryption.GenerateKey(masterKey, salt)
		decryptedValue, err = encryption.Decrypt(string(encryptedValue), encryptionKey)
		if err != nil {
			return nil, err
		}

		var metadata string
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			return nil, err
		}

		dataList[key] = map[string]string{
			"value":     string(decryptedValue),
			"data_type": dataType,
			"metadata":  metadata,
		}
	}
	return dataList, nil
}

// MasterKeyRotation rotates the master key used for encrypting private data.
// It decrypts all private data with the old master key, generates a new master key,
// re-encrypts the data with the new key, and updates the `.env` file with the new key.
func (s *PostgresStorage) MasterKeyRotation() {
	MASTER_KEY_ROTATION = true

	rows, err := s.DB.Query("SELECT id, data_value, salt FROM private_data")
	if err != nil {
		fmt.Printf("failed to fetch encryption keys: %v", err)
		return
	}
	defer rows.Close()

	// Получение мастер-ключа из переменной окружения
	oldMasterKey := os.Getenv("MASTER_KEY")
	if oldMasterKey == "" {
		fmt.Printf("master key not set")
		return
	}

	// Создаем новый MK
	newMasterKey, err := encryption.GenerateMasterKey()
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	for rows.Next() {
		var salt []byte
		var encryptedValue string
		var id int
		if err := rows.Scan(&id, &encryptedValue, &salt); err != nil {
			fmt.Printf("failed to scan row: %v", err)
			return
		}

		// Дешифруем ключ шифрования старым мастер-ключом
		oldEncryptionKey := encryption.GenerateKey(oldMasterKey, salt)
		// Дешифруем данные
		value, err := encryption.Decrypt(encryptedValue, oldEncryptionKey)
		if err != nil {
			fmt.Printf("failed to decrypt key with old master key: %v", err)
			return
		}

		if err := os.Setenv("MASTER_KEY", newMasterKey); err != nil {
			fmt.Printf("failed to set environment variable: %v", err)
			return
		}

		// Шифруем ключ шифрования новым мастер-ключом
		newEncryptionKey := encryption.GenerateKey(newMasterKey, salt)
		// Шифруем данные
		reencryptedValue, err := encryption.Encrypt(value, newEncryptionKey)
		if err != nil {
			fmt.Printf("failed to reencrypt key with new master key: %v", err)
			return
		}

		// Обновляем данные
		_, err = s.DB.Exec("UPDATE private_data SET data_value = $1 WHERE id = $2", reencryptedValue, id)
		if err != nil {
			fmt.Printf("failed to update encryption key in database: %v", err)
			return
		}
	}

	// Обновляем MASTER_KEY в файле .env
	if err := updateEnvFileWithGodotenv("MASTER_KEY", newMasterKey); err != nil {
		MASTER_KEY_ROTATION = false
		fmt.Printf("failed to update .env file: %v", err)
		return
	}

	fmt.Println("Master key rotation completed successfully.")
	MASTER_KEY_ROTATION = false

}

// updateEnvFileWithGodotenv updates the value of a variable in the `.env` file using godotenv.
func updateEnvFileWithGodotenv(key, value string) error {
	envFilePath := ".env"

	// Загрузка текущих переменных из .env
	envMap, err := godotenv.Read(envFilePath)
	if err != nil {
		// Если файл не существует, создаем пустую мапу
		envMap = make(map[string]string)
	}

	envMap[key] = value

	// Сохранение обратно в файл
	if err := godotenv.Write(envMap, envFilePath); err != nil {
		return fmt.Errorf("failed to write to .env file: %v", err)
	}

	return nil
}

// GetUserIDByLogin retrieves the unique identifier of a user based on their login.
func (s *PostgresStorage) GetUserIDByLogin(login string) (string, error) {
	query := "SELECT uid FROM users WHERE login = $1"
	var userID string
	err := s.DB.QueryRow(query, login).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// PingHandler checks the health of the database connection by pinging the database.
func (s *PostgresStorage) PingHandler() error {
	err := s.DB.Ping()
	return err
}

// Close closes the database connection.
func (s *PostgresStorage) Close() error {
	return s.DB.Close()
}
