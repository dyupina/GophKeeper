package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/asaskevich/govalidator"
)

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  register <login> <password>")
	fmt.Println("  login <login> <password>")
	fmt.Println("  read <key>")
	fmt.Println("  write <key> <value> <data_type>")
	fmt.Println("  delete <key>")
	fmt.Println("  list")
}

// registerUser sends a request to register a user.
func registerUser(login, password string) {
	if !isServerOnline {
		fmt.Println("Server is offline. Can't register")
		return
	}

	resp, err := client.R().
		SetBody(map[string]string{"login": login, "password": password}).
		Post("/register")

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if resp.IsSuccess() {
		var result map[string]string
		err := json.Unmarshal(resp.Body(), &result)
		if err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}
		fmt.Println("Registration successful. Token:", result["token"])
	} else {
		fmt.Println("Error:", string(resp.Body()))
	}
}

// loginUser sends a login request.
func loginUser(login, password string) {
	if !isServerOnline {
		fmt.Println("Server is offline. Can't login")
		return
	}

	resp, err := client.R().
		SetBody(map[string]string{"login": login, "password": password}).
		Post("/login")

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if resp.IsSuccess() {
		var result map[string]string
		err := json.Unmarshal(resp.Body(), &result)

		if err != nil {
			fmt.Println("Error parsing response:", err)
			return
		}
		token = result["token"]
		fmt.Println("Login successful. Token:", token)
	} else {
		fmt.Println("Error:", string(resp.Body()))
	}
}

// savePrivateData sends a request to save private data.
func savePrivateData(key, value, dataType string, metadata string) {
	if !isServerOnline {
		fmt.Println("Server is offline. Can't save data")
		return
	}

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+token).
		SetBody(map[string]string{
			"key":       key,
			"value":     value,
			"data_type": dataType,
			"metadata":  metadata,
		}).
		Post("/save")

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	if resp.IsSuccess() {
		// Обновляем кеш
		cacheMutex.Lock()
		localCache[key] = map[string]interface{}{
			"value":     value,
			"data_type": dataType,
			"metadata":  metadata,
		}
		cacheMutex.Unlock()

		fmt.Println("Data saved successfully")
	} else {
		fmt.Println("Error:", string(resp.Body()))
	}
}

// getPrivateData sends a request to get private data.
func getPrivateData(key string) {
	if isServerOnline {
		resp, err := client.R().
			SetHeader("Authorization", "Bearer "+token).
			SetBody(map[string]string{"key": key}).
			Post("/get")

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if resp.IsSuccess() {
			var result map[string]interface{}
			err := json.Unmarshal(resp.Body(), &result)
			if err != nil {
				fmt.Println("Error parsing response:", err)
				return
			}

			// Обновляем кеш
			cacheMutex.Lock()
			localCache[key] = result
			cacheMutex.Unlock()

			fmt.Printf("Retrieved data: %+v\n", result)
		} else {
			fmt.Println("Error:", string(resp.Body()))
		}
	} else {
		fmt.Println("Server is offline. Read from local cache")

		cacheMutex.Lock()
		defer cacheMutex.Unlock()
		result, exists := localCache[key]
		if !exists {
			fmt.Println("Error: data not found in cache")
			return
		}
		fmt.Printf("Retrieved data: %+v\n", result)
	}
}

// deleteData sends a request to delete private data.
func deleteData(key string) {
	if !isServerOnline {
		fmt.Println("Server is offline. Can't delete data")
		return
	}

	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+token).
		SetBody(map[string]string{"key": key}).
		Post("/delete")

	if err != nil {
		fmt.Println("Error deleting data:", err)
		return
	}

	if resp.IsSuccess() {
		// Удаляем запись из локального кеша
		cacheMutex.Lock()
		defer cacheMutex.Unlock()
		if _, exists := localCache[key]; exists {
			delete(localCache, key)
			fmt.Printf("Key '%s' removed from local cache\n", key)
		}

		fmt.Println("Data deleted successfully")
	} else {
		fmt.Println("Error:", string(resp.Body()))
	}
}

// listData sends a request to display private data.
func listData() {
	if isServerOnline {
		resp, err := client.R().
			SetHeader("Authorization", "Bearer "+token).
			Get("/list")

		if err != nil {
			fmt.Println("Error listing data:", err)
			return
		}

		if resp.IsSuccess() {
			var dataList map[string]map[string]interface{}
			err := json.Unmarshal(resp.Body(), &dataList)
			if err != nil {
				fmt.Println("Error parsing response:", err)
				return
			}

			if len(dataList) == 0 {
				fmt.Println("No data found")
				return
			}

			// Обновляем локальный кеш
			cacheMutex.Lock()
			localCache = dataList
			cacheMutex.Unlock()

			printDataList(dataList)
			return
		} else {
			fmt.Println("Error:", string(resp.Body()))
		}

		// Если запрос на сервер завершился ошибкой, переходим в режим read-only
		fmt.Println("Failed to fetch data from server. Using local cache.")
	} else {
		fmt.Println("Server is offline. Read from local cache")

		// Используем локальный кеш
		cacheMutex.Lock()
		defer cacheMutex.Unlock()

		if len(localCache) == 0 {
			fmt.Println("No data found in cache")
			return
		}

		printDataList(localCache)
	}
}

// printDataList prints the contents of the dataList map in a human-readable format.
func printDataList(dataList map[string]map[string]interface{}) {
	fmt.Println("Data list:")
	for key, data := range dataList {
		fmt.Printf("Key: %s\n", key)
		fmt.Printf("  Value: %s\n", data["value"])
		fmt.Printf("  Type: %s\n", data["data_type"])
		fmt.Printf("  Metadata: %+v\n", data["metadata"])
	}
}

// checkAuth checks if the user is authenticated by verifying the presence of a token.
func checkAuth() bool {
	if token == "" {
		fmt.Println("You need to login first")
		return false
	}
	return true
}

// checkServerAvailability continuously checks the availability of the server.
func checkServerAvailability() {
	for {
		resp, err := client.R().Get("/ping")

		if err == nil && resp.IsSuccess() {
			isServerOnline = true
		} else {
			isServerOnline = false
		}

		time.Sleep(1 * time.Second) // Проверка каждую секунду
	}
}

// validateBankCard validates the provided bank card details.
func validateBankCard(cardNumber, expiryDate, cvv string) bool {
	// Валидация номера карты (только цифры, длина 13-19)
	if !govalidator.IsNumeric(cardNumber) || len(cardNumber) < 13 || len(cardNumber) > 19 {
		fmt.Println("Invalid card number")
		return false
	}

	// Валидация срока действия (формат MM/YY)
	if !govalidator.Matches(expiryDate, `^(0[1-9]|1[0-2])\/\d{2}$`) {
		fmt.Println("Invalid expiry date")
		return false
	}

	// Валидация CVV (только цифры, длина 3)
	if !govalidator.IsNumeric(cvv) || len(cvv) < 3 {
		fmt.Println("Invalid CVV")
		return false
	}

	return true
}
