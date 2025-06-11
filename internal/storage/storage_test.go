package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"gophkeeper/internal/encryption"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestSaveLoginPassword(t *testing.T) {
	tests := []struct {
		name           string
		login          string
		hashedPassword string
		mockBehavior   func(mock sqlmock.Sqlmock)
		expectedResult bool
	}{
		{
			name:           "Successful save",
			login:          "testuser",
			hashedPassword: "hashedpassword",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO users").
					WithArgs("testuser", "hashedpassword").
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectedResult: true,
		},
		{
			name:           "Failed save due to database error",
			login:          "testuser",
			hashedPassword: "hashedpassword",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO users").
					WithArgs("testuser", "hashedpassword").
					WillReturnError(errors.New("database error"))
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}

			tt.mockBehavior(mock)

			result := storage.SaveLoginPassword(tt.login, tt.hashedPassword)

			assert.Equal(t, tt.expectedResult, result, "SaveLoginPassword result does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetHashedPasswordByLogin(t *testing.T) {
	tests := []struct {
		name           string
		login          string
		mockBehavior   func(mock sqlmock.Sqlmock)
		expectedResult string
	}{
		{
			name:  "Successful retrieval",
			login: "testuser",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"password"}).AddRow("hashedpassword")
				mock.ExpectQuery("SELECT password FROM users WHERE login").
					WithArgs("testuser").
					WillReturnRows(rows)
			},
			expectedResult: "hashedpassword",
		},
		{
			name:  "User not found",
			login: "nonexistentuser",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT password FROM users WHERE login").
					WithArgs("nonexistentuser").
					WillReturnError(sql.ErrNoRows)
			},
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}

			tt.mockBehavior(mock)

			result := storage.GetHashedPasswordByLogin(tt.login)

			assert.Equal(t, tt.expectedResult, result, "GetHashedPasswordByLogin result does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		expectedError error
	}{
		{
			name:          "Valid password",
			password:      "strongpassword123",
			expectedError: nil,
		},
		{
			name:          "Empty password",
			password:      "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &PostgresStorage{}

			hashedPassword, err := storage.HashPassword(tt.password)

			assert.Equal(t, tt.expectedError, err, "HashPassword error does not match expected")

			if tt.expectedError == nil {
				err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(tt.password))
				assert.NoError(t, err, "Hashed password does not match the original password")
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		hash           string
		expectedResult bool
	}{
		{
			name:           "Valid password and hash",
			password:       "strongpassword123",
			hash:           generateHashForTest("strongpassword123"),
			expectedResult: true,
		},
		{
			name:           "Invalid password",
			password:       "wrongpassword",
			hash:           generateHashForTest("strongpassword123"),
			expectedResult: false,
		},
		{
			name:           "Empty password and hash",
			password:       "",
			hash:           generateHashForTest(""),
			expectedResult: true,
		},
		{
			name:           "Invalid hash format",
			password:       "strongpassword123",
			hash:           "invalidhash",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &PostgresStorage{}
			result := storage.CheckPasswordHash(tt.password, tt.hash)
			assert.Equal(t, tt.expectedResult, result, "CheckPasswordHash result does not match expected")
		})
	}
}

func generateHashForTest(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func TestSaveUID(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		login         string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:   "Successful update",
			userID: "user123",
			login:  "testuser",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("UPDATE users SET uid").
					WithArgs("user123", "testuser").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			expectedError: nil,
		},
		{
			name:   "Failed update due to database error",
			userID: "user123",
			login:  "testuser",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("UPDATE users SET uid").
					WithArgs("user123", "testuser").
					WillReturnError(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}
			tt.mockBehavior(mock)
			err = storage.SaveUID(tt.userID, tt.login)
			assert.Equal(t, tt.expectedError, err, "SaveUID error does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestSaveToken(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		token         string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:   "Successful save",
			userID: "user123",
			token:  "newtoken",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO tokens").
					WithArgs("user123", "newtoken").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			expectedError: nil,
		},
		{
			name:   "Failed save due to database error",
			userID: "user123",
			token:  "newtoken",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO tokens").
					WithArgs("user123", "newtoken").
					WillReturnError(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}
			tt.mockBehavior(mock)
			err = storage.SaveToken(tt.userID, tt.token)
			assert.Equal(t, tt.expectedError, err, "SaveToken error does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetTokenByUserID(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedToken string
		expectedError error
	}{
		{
			name:   "Successful retrieval",
			userID: "user123",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"token"}).AddRow("existingtoken")
				mock.ExpectQuery("SELECT token FROM tokens WHERE uid").
					WithArgs("user123").
					WillReturnRows(rows)
			},
			expectedToken: "existingtoken",
			expectedError: nil,
		},
		{
			name:   "Token not found",
			userID: "user123",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT token FROM tokens WHERE uid").
					WithArgs("user123").
					WillReturnError(sql.ErrNoRows)
			},
			expectedToken: "",
			expectedError: nil,
		},
		{
			name:   "Database error",
			userID: "user123",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT token FROM tokens WHERE uid").
					WithArgs("user123").
					WillReturnError(errors.New("database error"))
			},
			expectedToken: "",
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}
			tt.mockBehavior(mock)
			token, err := storage.GetTokenByUserID(tt.userID)

			assert.Equal(t, tt.expectedToken, token, "GetTokenByUserID token does not match expected")
			assert.Equal(t, tt.expectedError, err, "GetTokenByUserID error does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestSavePrivateData(t *testing.T) {
	originalMasterKey := os.Getenv("MASTER_KEY")
	defer func() {
		if err := os.Setenv("MASTER_KEY", originalMasterKey); err != nil {
			t.Logf("failed to restore MASTER_KEY: %v", err)
		}
	}()

	if originalMasterKey == "" {
		newMasterKey := "test_master_key"
		if err := os.Setenv("MASTER_KEY", newMasterKey); err != nil {
			t.Fatalf("failed to set MASTER_KEY: %v", err)
		}
	}

	tests := []struct {
		name          string
		userID        string
		key           string
		value         string
		dataType      string
		metadata      string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:     "Successful save",
			userID:   "user123",
			key:      "key1",
			value:    "value1",
			dataType: "type1",
			metadata: "metadata1",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO private_data").
					WithArgs(sqlmock.AnyArg(), "key1", sqlmock.AnyArg(), "type1", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			expectedError: nil,
		},
		{
			name:     "Failed save due to database error",
			userID:   "user123",
			key:      "key1",
			value:    "value1",
			dataType: "type1",
			metadata: "metadata1",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("INSERT INTO private_data").
					WithArgs(sqlmock.AnyArg(), "key1", sqlmock.AnyArg(), "type1", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}
			tt.mockBehavior(mock)
			err = storage.SavePrivateData(tt.userID, tt.key, tt.value, tt.dataType, tt.metadata)
			assert.Equal(t, tt.expectedError, err, "SavePrivateData error does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestDeletePrivateData(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		key           string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedRows  int64
		expectedError error
	}{
		{
			name:   "Successful deletion",
			userID: "user123",
			key:    "key1",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("DELETE FROM private_data").
					WithArgs("user123", "key1").
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			expectedRows:  1,
			expectedError: nil,
		},
		{
			name:   "No rows deleted",
			userID: "user123",
			key:    "key1",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("DELETE FROM private_data").
					WithArgs("user123", "key1").
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			expectedRows:  0,
			expectedError: nil,
		},
		{
			name:   "Database error",
			userID: "user123",
			key:    "key1",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec("DELETE FROM private_data").
					WithArgs("user123", "key1").
					WillReturnError(errors.New("database error"))
			},
			expectedRows:  0,
			expectedError: errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create sqlmock: %v", err)
			}
			defer db.Close()

			storage := &PostgresStorage{DB: db}
			tt.mockBehavior(mock)
			rowsAffected, err := storage.DeletePrivateData(tt.userID, tt.key)

			assert.Equal(t, tt.expectedRows, rowsAffected, "DeletePrivateData rows affected does not match expected")
			assert.Equal(t, tt.expectedError, err, "DeletePrivateData error does not match expected")

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetUserIDByLogin(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	storage := &PostgresStorage{DB: db}

	login := "testuser"
	userID := "user123"

	tests := []struct {
		name           string
		login          string
		mockBehavior   func(mock sqlmock.Sqlmock)
		expectedUserID string
		expectedError  error
	}{
		{
			name:  "User found",
			login: login,
			mockBehavior: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"uid"}).AddRow(userID)
				mock.ExpectQuery("SELECT uid FROM users WHERE login").
					WithArgs(login).
					WillReturnRows(rows)
			},
			expectedUserID: userID,
			expectedError:  nil,
		},
		{
			name:  "User not found",
			login: "nonexistentuser",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT uid FROM users WHERE login").
					WithArgs("nonexistentuser").
					WillReturnError(sql.ErrNoRows)
			},
			expectedUserID: "",
			expectedError:  ErrUserNotFound,
		},
		{
			name:  "Database error",
			login: login,
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery("SELECT uid FROM users WHERE login").
					WithArgs(login).
					WillReturnError(errors.New("database error"))
			},
			expectedUserID: "",
			expectedError:  errors.New("database error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior(mock)
			userID, err := storage.GetUserIDByLogin(tt.login)

			assert.Equal(t, tt.expectedUserID, userID, "GetUserIDByLogin userID does not match expected")
			assert.Equal(t, tt.expectedError, err, "GetUserIDByLogin error does not match expected")

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestClose(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	storage := &PostgresStorage{DB: db}

	tests := []struct {
		name          string
		mockBehavior  func(mock sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name: "Successful close",
			mockBehavior: func(mock sqlmock.Sqlmock) {
				mock.ExpectClose().WillReturnError(nil)
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockBehavior(mock)
			err := storage.Close()
			assert.Equal(t, tt.expectedError, err, "Close error does not match expected")
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetPrivateData(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	storage := &PostgresStorage{DB: db}

	userID := "user-123"
	key := "my_key"

	tests := []struct {
		name          string
		setupMock     func()
		expectedValue string
		expectedType  string
		expectedMeta  string
		expectedErr   error
		setMasterKey  bool
	}{
		{
			name: "Success",
			setupMock: func() {
				masterKey := "test_master_key"
				userID := "user-123"
				key := "my_key"

				// Фиксируем salt
				salt := []byte("1234567890123456") // 16 байт = SaltSize

				plaintext := []byte("secret_data")
				encryptionKey := encryption.GenerateKey(masterKey, salt)

				ciphertext, _ := encryption.Encrypt(plaintext, encryptionKey)

				metadataJSON, _ := json.Marshal("meta_info")

				rows := sqlmock.NewRows([]string{"data_value", "data_type", "metadata", "salt"}).
					AddRow(
						ciphertext,
						"text",
						metadataJSON,
						salt,
					)

				mock.ExpectQuery(`SELECT data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1 AND data_key = \$2`).
					WithArgs(userID, key).
					WillReturnRows(rows)
			},
			expectedValue: "secret_data",
			expectedType:  "text",
			expectedMeta:  "meta_info",
			expectedErr:   nil,
			setMasterKey:  true,
		},
		{
			name: "DataNotFound",
			setupMock: func() {
				mock.ExpectQuery(`SELECT data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1 AND data_key = \$2`).
					WithArgs(userID, key).
					WillReturnError(sql.ErrNoRows)
			},
			expectedValue: "",
			expectedType:  "",
			expectedMeta:  "",
			expectedErr:   nil,
			setMasterKey:  true,
		},
		{
			name: "DecryptionFailed",
			setupMock: func() {
				salt := []byte("1234567890123456") // фиксированный salt
				metadataJSON, _ := json.Marshal("meta_info")

				// Передаём невалидный зашифрованный текст
				rows := sqlmock.NewRows([]string{"data_value", "data_type", "metadata", "salt"}).
					AddRow(
						"invalid_base64",
						"text",
						metadataJSON,
						salt,
					)

				mock.ExpectQuery(`SELECT data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1 AND data_key = \$2`).
					WithArgs(userID, key).
					WillReturnRows(rows)
			},
			expectedValue: "",
			expectedType:  "",
			expectedMeta:  "",
			expectedErr:   errors.New("illegal base64 data at input byte 7"),
			setMasterKey:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setMasterKey {
				os.Setenv("MASTER_KEY", "test_master_key")
			} else {
				os.Unsetenv("MASTER_KEY")
			}

			tt.setupMock()

			value, dType, meta, err := storage.GetPrivateData(userID, key)

			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedType, dType)
			assert.Equal(t, tt.expectedMeta, meta)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}

			err = mock.ExpectationsWereMet()
			assert.NoError(t, err)
		})
	}
}

func TestListPrivateData(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	storage := &PostgresStorage{DB: db}

	userID := "user-123"

	tests := []struct {
		name             string
		setupMock        func()
		expectedResponse map[string]map[string]string
		expectedErr      error
		setMasterKey     bool
	}{
		{
			name: "Success",
			setupMock: func() {
				salt := []byte("1234567890123456")
				masterKey := "test_master_key"
				key := encryption.GenerateKey(masterKey, salt)

				plaintext := []byte("secret_data")
				ciphertext, _ := encryption.Encrypt(plaintext, key)

				metadataJSON, _ := json.Marshal("meta_info")

				rows := sqlmock.NewRows([]string{"data_key", "data_value", "data_type", "metadata", "salt"}).
					AddRow(
						"key1",
						ciphertext,
						"text",
						metadataJSON,
						salt,
					)

				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			expectedResponse: map[string]map[string]string{
				"key1": {
					"value":     "secret_data",
					"data_type": "text",
					"metadata":  "meta_info",
				},
			},
			expectedErr:  nil,
			setMasterKey: true,
		},
		{
			name: "Success_EmptyList",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"data_key", "data_value", "data_type", "metadata", "salt"})
				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			expectedResponse: map[string]map[string]string{},
			expectedErr:      nil,
			setMasterKey:     true,
		},
		{
			name: "MasterKeyNotSet",
			setupMock: func() {
				salt := []byte("1234567890123456")
				masterKey := "test_master_key"
				key := encryption.GenerateKey(masterKey, salt)

				plaintext := []byte("secret_data")
				ciphertext, _ := encryption.Encrypt(plaintext, key)

				metadataJSON, _ := json.Marshal("meta_info")

				rows := sqlmock.NewRows([]string{"data_key", "data_value", "data_type", "metadata", "salt"}).
					AddRow(
						"key1",
						ciphertext,
						"text",
						metadataJSON,
						salt,
					)

				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			expectedResponse: nil,
			expectedErr:      ErrMKNotSet,
			setMasterKey:     false,
		},
		{
			name: "DecryptionFailed",
			setupMock: func() {
				salt := []byte("1234567890123456")
				rows := sqlmock.NewRows([]string{"data_key", "data_value", "data_type", "metadata", "salt"}).
					AddRow(
						"key1",
						"invalid_base64",
						"text",
						[]byte("{}"),
						salt,
					)

				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			expectedResponse: nil,
			expectedErr:      errors.New("illegal base64 data at input byte 7"),
			setMasterKey:     true,
		},
		{
			name: "DatabaseError",
			setupMock: func() {
				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnError(errors.New("db connection failed"))
			},
			expectedResponse: nil,
			expectedErr:      errors.New("db connection failed"),
			setMasterKey:     true,
		},
		{
			name: "ScanError",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"data_key", "data_value", "data_type", "metadata", "salt"}).
					AddRow(nil, nil, nil, nil, nil)

				mock.ExpectQuery(`SELECT data_key, data_value, data_type, metadata, salt FROM private_data WHERE uid = \$1`).
					WithArgs(userID).
					WillReturnRows(rows)
			},
			expectedResponse: nil,
			expectedErr:      errors.New("converting NULL to string"),
			setMasterKey:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setMasterKey {
				os.Setenv("MASTER_KEY", "test_master_key")
			} else {
				os.Unsetenv("MASTER_KEY")
			}

			tt.setupMock()

			result, err := storage.ListPrivateData(userID)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, result)
			}

			err = mock.ExpectationsWereMet()
			assert.NoError(t, err)
		})
	}
}

func TestPingHandler(t *testing.T) {
	db, _, err := sqlmock.New()
	assert.NoError(t, err)
	defer db.Close()

	storage := &PostgresStorage{DB: db}
	err = storage.PingHandler()

	assert.NoError(t, err)
}

func TestUpDBMigrations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		uid      TEXT UNIQUE,
		login TEXT UNIQUE NOT NULL,
		password BYTEA NOT NULL
	);`).WillReturnResult(sqlmock.NewResult(1, 1))

	UpDBMigrations(db)
}
