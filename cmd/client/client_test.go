package main

import (
	"encoding/json"
	"gophkeeper/internal/config"
	"gophkeeper/internal/handlers"
	"gophkeeper/internal/logger"
	"gophkeeper/internal/routing"
	"gophkeeper/internal/storage"
	"gophkeeper/internal/user"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-resty/resty/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}

func setTestClient(serverURL string) {
	client = resty.New()
	client.SetBaseURL(serverURL)
}

func TestRegisterUser(t *testing.T) {
	printUsage()
	server := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "testuser", body["login"])
		assert.Equal(t, "testpass", body["password"])

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "testtoken"})
	})
	defer server.Close()

	setTestClient(server.URL)

	registerUser("testuser", "testpass")
}

func TestLoginUser(t *testing.T) {
	server := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "testuser", body["login"])
		assert.Equal(t, "testpass", body["password"])

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "testtoken"})
	})
	defer server.Close()

	setTestClient(server.URL)

	loginUser("testuser", "testpass")
	assert.Equal(t, "testtoken", token)
}

func TestLoginUser_InvalidResponse(t *testing.T) {
	server := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid-json`)) // Невалидный JSON
	})
	defer server.Close()

	setTestClient(server.URL)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	loginUser("testuser", "testpass")

	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	assert.Contains(t, string(out), "Error parsing response:")
}

func TestSavePrivateData(t *testing.T) {
	server := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer testtoken", auth)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), `"key":"mykey"`)
		assert.Contains(t, string(body), `"value":"myvalue"`)

		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "Saved")
	})
	defer server.Close()

	setTestClient(server.URL)
	token = "testtoken"

	savePrivateData("mykey", "myvalue", "text", "meta")

	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	data, exists := localCache["mykey"]
	assert.True(t, exists)
	assert.Equal(t, "myvalue", data["value"])
}

func TestGetPrivateData(t *testing.T) {
	tests := []struct {
		name             string
		serverHandler    http.HandlerFunc
		isServerOnline   bool
		initialCache     map[string]map[string]interface{}
		key              string
		expectedValue    interface{}
		expectedInCache  bool
		expectedOutput   string
		expectedNoOutput string
	}{
		{
			name: "Success - Data fetched from server",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer testtoken", auth)

				var body map[string]string
				err := json.NewDecoder(r.Body).Decode(&body)
				require.NoError(t, err)
				assert.Equal(t, "key1", body["key"])

				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value":     "secret",
					"data_type": "text",
					"metadata":  "meta info",
				})
			},
			isServerOnline:  true,
			key:             "key1",
			expectedValue:   "secret",
			expectedInCache: true,
			expectedOutput:  "Retrieved data:",
		},
		{
			name: "Invalid JSON response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`invalid-json`))
			},
			isServerOnline:  true,
			key:             "key1",
			expectedInCache: false,
			expectedOutput:  "Error parsing response",
		},
		{
			name: "Server returns error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Internal Server Error"}`))
			},
			isServerOnline:  true,
			key:             "key1",
			expectedInCache: false,
			expectedOutput:  "Error: {\"error\": \"Internal Server Error\"}",
		},
		{
			name:           "Server offline - Read from local cache",
			serverHandler:  nil,
			isServerOnline: false,
			initialCache: map[string]map[string]interface{}{
				"offline_key": {"value": "offline_val", "data_type": "text", "metadata": "offline_meta"},
			},
			key:             "offline_key",
			expectedValue:   "offline_val",
			expectedInCache: true,
			expectedOutput:  "Retrieved data:",
		},
		{
			name:           "Server offline - Key not found in cache",
			serverHandler:  nil,
			isServerOnline: false,
			initialCache: map[string]map[string]interface{}{
				"another_key": {"value": "some_val", "data_type": "text", "metadata": "meta"},
			},
			key:              "missing_key",
			expectedInCache:  false,
			expectedOutput:   "Error: data not found in cache",
			expectedNoOutput: "Retrieved data:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Подавляем вывод в stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Создаем мок-сервер, если нужен
			var server *httptest.Server
			if tt.serverHandler != nil {
				server = mockServer(t, tt.serverHandler)
				defer server.Close()
			} else {
				// Если сервер не нужен — создаём заглушку
				server = mockServer(t, func(w http.ResponseWriter, r *http.Request) {})
				defer server.Close()
			}

			// Настраиваем клиент и токен
			setTestClient(server.URL)
			token = "testtoken"
			isServerOnline = tt.isServerOnline

			// Инициализируем локальный кэш
			cacheMutex.Lock()
			localCache = tt.initialCache
			if localCache == nil {
				localCache = make(map[string]map[string]interface{})
			}
			cacheMutex.Unlock()

			getPrivateData(tt.key)

			// Восстанавливаем stdout и получаем вывод
			_ = w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = oldStdout

			cacheMutex.Lock()
			data, exists := localCache[tt.key]
			cacheMutex.Unlock()

			assert.Equal(t, tt.expectedInCache, exists)
			if tt.expectedInCache && exists {
				assert.Equal(t, tt.expectedValue, data["value"])
			}

			assert.Contains(t, string(out), tt.expectedOutput)
			if tt.expectedNoOutput != "" {
				assert.NotContains(t, string(out), tt.expectedNoOutput)
			}
		})
	}
}

func TestDeleteData(t *testing.T) {
	tests := []struct {
		name             string
		serverHandler    http.HandlerFunc
		isServerOnline   bool
		initialCache     map[string]interface{}
		key              string
		expectedInCache  bool
		expectedOutput   string
		expectedNoOutput string
	}{
		{
			name: "Success - Data deleted from server and cache",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				assert.Equal(t, "Bearer testtoken", auth)

				var body map[string]string
				err := json.NewDecoder(r.Body).Decode(&body)
				require.NoError(t, err)
				assert.Equal(t, "key1", body["key"])

				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "Deleted")
			},
			isServerOnline: true,
			initialCache: map[string]interface{}{
				"value": "val1",
			},
			key:              "key1",
			expectedInCache:  false,
			expectedOutput:   "Data deleted successfully",
			expectedNoOutput: "Error:",
		},
		{
			name:           "Server offline - Can't delete data",
			serverHandler:  nil,
			isServerOnline: false,
			initialCache: map[string]interface{}{
				"value": "val1",
			},
			key:              "key1",
			expectedInCache:  true,
			expectedOutput:   "Server is offline. Can't delete data",
			expectedNoOutput: "Key 'key1' removed from local cache",
		},
		{
			name: "Server returns error - Not success status",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, "Internal Server Error")
			},
			isServerOnline: true,
			initialCache: map[string]interface{}{
				"value": "val1",
			},
			key:              "key1",
			expectedInCache:  true,
			expectedOutput:   "Error: Internal Server Error",
			expectedNoOutput: "Data deleted successfully",
		},
		{
			name: "Key not found in cache",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "Deleted")
			},
			isServerOnline:  true,
			initialCache:    nil,
			key:             "nonexistent_key",
			expectedInCache: false,
			expectedOutput:  "Data deleted successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Подавляем вывод в stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Создаем мок-сервер
			var server *httptest.Server
			if tt.serverHandler != nil {
				server = mockServer(t, tt.serverHandler)
			} else {
				// Если сервер не нужен — создаём заглушку
				server = mockServer(t, func(w http.ResponseWriter, r *http.Request) {})
			}
			defer server.Close()

			// Настраиваем клиент и токен
			setTestClient(server.URL)
			token = "testtoken"
			isServerOnline = tt.isServerOnline

			// Инициализируем локальный кэш
			cacheMutex.Lock()
			localCache[tt.key] = tt.initialCache
			cacheMutex.Unlock()

			deleteData(tt.key)

			// Восстанавливаем stdout и получаем вывод
			_ = w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = oldStdout

			// Проверяем, есть ли ключ в кэше
			cacheMutex.Lock()
			_, exists := localCache[tt.key]
			cacheMutex.Unlock()

			assert.Equal(t, tt.expectedInCache, exists)

			// Проверяем вывод
			assert.Contains(t, string(out), tt.expectedOutput)
			if tt.expectedNoOutput != "" {
				assert.NotContains(t, string(out), tt.expectedNoOutput)
			}
		})
	}
}

func TestListData(t *testing.T) {
	tests := []struct {
		name             string
		serverHandler    http.HandlerFunc
		isServerOnline   bool
		initialCache     map[string]map[string]interface{}
		expectedInCache  []string
		expectedNotCache []string
		expectOutput     string
	}{
		{
			name: "Success - Data fetched from server",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth != "Bearer testtoken" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]map[string]interface{}{
					"key1": {"value": "val1", "data_type": "text", "metadata": "meta1"},
					"key2": {"value": "val2", "data_type": "text", "metadata": "meta2"},
				})
			},
			isServerOnline: true,
			initialCache:   nil,
			expectedInCache: []string{
				"key1",
				"key2",
			},
			expectOutput: "Key: key1",
		},
		{
			name: "Server offline - Read from local cache",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			},
			isServerOnline: false,
			initialCache: map[string]map[string]interface{}{
				"offline_key": {"value": "offline_val", "data_type": "text", "metadata": "offline_meta"},
			},
			expectedInCache: []string{"offline_key"},
			expectOutput:    "offline_val",
		},
		{
			name: "Empty response from server",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("{}")) // empty JSON
			},
			isServerOnline: true,
			initialCache:   nil,
			expectedNotCache: []string{
				"anykey",
			},
			expectOutput: "No data found",
		},
		{
			name: "Invalid JSON response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("invalid-json"))
			},
			isServerOnline: true,
			initialCache:   nil,
			expectedNotCache: []string{
				"anykey",
			},
			expectOutput: "Error parsing response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Подавляем вывод в консоль
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			server := mockServer(t, tt.serverHandler)
			defer server.Close()

			setTestClient(server.URL)
			token = "testtoken"
			isServerOnline = tt.isServerOnline

			cacheMutex.Lock()
			localCache = tt.initialCache
			if localCache == nil {
				localCache = make(map[string]map[string]interface{})
			}
			cacheMutex.Unlock()

			listData()

			// Восстанавливаем stdout и получаем вывод
			w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = old

			// Проверяем содержимое кэша
			cacheMutex.Lock()
			for _, key := range tt.expectedInCache {
				assert.Contains(t, localCache, key)
			}
			for _, key := range tt.expectedNotCache {
				assert.NotContains(t, localCache, key)
			}
			cacheMutex.Unlock()

			// Проверяем вывод в консоль
			assert.Contains(t, string(out), tt.expectOutput)
		})
	}
}

func TestValidateBankCard(t *testing.T) {
	assert.True(t, validateBankCard("4111111111111111", "12/25", "123"))
	assert.False(t, validateBankCard("abc", "12/25", "123"))
	assert.False(t, validateBankCard("4111111111111111", "13/25", "123"))
	assert.False(t, validateBankCard("4111111111111111", "12/25", "12"))
}

func TestCheckServerAvailability(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectedStatus bool
	}{
		{
			name: "Server is available",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus: true,
		},
		{
			name: "Server is unavailable",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			expectedStatus: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := mockServer(t, tt.serverResponse)
			defer server.Close()

			setTestClient(server.URL)
			isServerOnline = false

			// Запускаем checkServerAvailability в фоне
			done := make(chan bool)
			go func() {
				time.AfterFunc(2*time.Second, func() {
					close(done)
				})
				checkServerAvailability()
			}()

			// Ждём, пока произойдёт хотя бы один пинг
			<-done

			assert.Equal(t, tt.expectedStatus, isServerOnline)
		})
	}
}

func TestCheckAuth(t *testing.T) {
	oldToken := token
	defer func() { token = oldToken }()

	token = ""
	assert.False(t, checkAuth())

	token = "testtoken"
	assert.True(t, checkAuth())
}

func TestPrintDataList(t *testing.T) {
	// Перехватываем stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	dataList := map[string]map[string]interface{}{
		"key1": {
			"value":     "secret",
			"data_type": "text",
			"metadata":  "meta info",
		},
	}

	printDataList(dataList)

	// Восстанавливаем stdout
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	// Проверяем вывод
	output := string(out)
	assert.Contains(t, output, "Key: key1")
	assert.Contains(t, output, "Value: secret")
	assert.Contains(t, output, "Type: text")
	assert.Contains(t, output, "Metadata: meta info")
}

func TestInit_(t *testing.T) {
	// Создаем временный файл сертификата
	tmpfile, err := os.CreateTemp("", "cert")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	_, _ = tmpfile.WriteString("fake-cert-data")

	// Перехватываем вывод
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Вызываем тестируемую функцию
	init_(tmpfile.Name())

	// Восстанавливаем stdout
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old

	// Проверяем, что логгер инициализирован
	assert.Contains(t, string(out), "Build version:")
}

func TestCreateServer(t *testing.T) {
	cfg := &config.Config{
		Addr: ":0", // random port
	}
	logger, _ := logger.NewLogger()
	srv := routing.CreateServer(cfg, chi.NewRouter(), logger)
	assert.NotNil(t, srv)
}

func TestRouting(t *testing.T) {
	c := config.NewConfig()
	_ = config.Init(c)
	s, _ := storage.NewPostgresStorage(c.DBConnection)
	userService := user.NewUserService(s)
	ctrl := handlers.NewController(c, s, nil, userService)

	r := chi.NewRouter()
	routing.Routing(r, ctrl)

	req := httptest.NewRequest("GET", "/ping", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClientMain(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"client", "register"} // эмуляция командной строки

	done := make(chan bool)
	go func() {
		defer func() {
			recover() // паники от тестов
		}()
		main()
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.FailNow()
	}
}

func TestInitMiddleware(t *testing.T) {
	r := chi.NewRouter()
	conf := &config.Config{}
	ctrl := &handlers.Controller{}

	routing.InitMiddleware(r, conf, ctrl)

	// проверка, что middleware применяются (нет паники)
	req := httptest.NewRequest("GET", "/ping", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
}
