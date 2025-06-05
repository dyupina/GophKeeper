package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/chzyer/readline"
	"github.com/go-resty/resty/v2"
)

var token string
var client *resty.Client
var localCache = make(map[string]map[string]interface{})
var cacheMutex sync.Mutex
var isServerOnline = true
var rl *readline.Instance

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
)

func init_(crt string) {
	caCert, err := os.ReadFile(crt)
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client = resty.New()
	client.SetBaseURL("https://localhost:8085")
	client.SetTLSClientConfig(&tls.Config{
		RootCAs: caCertPool,
	})

	rl, err = readline.NewEx(&readline.Config{
		Prompt:          "> ",
		HistoryFile:     "/tmp/readline_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completer(),
	})
	if err != nil {
		log.Fatalf("Failed to initialize readline: %v", err)
	}

	fmt.Printf("Build version: %s\n", buildVersion)
	fmt.Printf("Build date: %s\n", buildDate)
}

// completer is a AutoComplete function for readline.
func completer() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("register"),
		readline.PcItem("login"),
		readline.PcItem("read"),
		readline.PcItem("write"),
		readline.PcItem("delete"),
		readline.PcItem("list"),
		readline.PcItem("exit"),
		readline.PcItem("help"),
	)
}

func main() {
	init_("https/localhost.crt")
	printUsage()

	go checkServerAvailability()

	for {
		command, err := rl.Readline()
		if err != nil { // Обработка ошибок (например, Ctrl+D)
			break
		}

		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}

		switch command {
		case "register":
			rl.SetPrompt("Enter login: ")
			login, _ := rl.Readline()
			password, _ := rl.ReadPassword("Enter password: ")
			registerUser(login, string(password))
		case "login":
			rl.SetPrompt("Enter login: ")
			login, _ := rl.Readline()
			password, _ := rl.ReadPassword("Enter password: ")
			loginUser(login, string(password))
		case "read":
			if !checkAuth() {
				continue
			}
			rl.SetPrompt("Enter key: ")
			key, _ := rl.Readline()
			getPrivateData(key)
		case "write":
			if !checkAuth() {
				continue
			}
			rl.SetPrompt("Enter key: ")
			key, _ := rl.Readline()

			key = strings.TrimSpace(key)
			if key == "" {
				rl.SetPrompt("> ")
				continue
			}

			// Выбор типа данных
			fmt.Println("Select data type:")
			fmt.Println("1. Login/Password")
			fmt.Println("2. Text")
			fmt.Println("3. Binary (files)")
			fmt.Println("4. Bank Card")
			var dataType string

			rl.SetPrompt("Enter choice (1-4): ")
			dataTypeChoice, _ := rl.Readline()

			switch dataTypeChoice {
			case "1":
				dataType = "login_password"
			case "2":
				dataType = "text"
			case "3":
				dataType = "binary"
			case "4":
				dataType = "bank_card"
			default:
				fmt.Println("Invalid choice")
				rl.SetPrompt("> ")
				continue
			}

			// Запрашиваем значение в зависимости от типа данных
			var value string
			switch dataType {
			case "login_password":
				rl.SetPrompt("Enter login: ")
				login, _ := rl.Readline()

				login = strings.TrimSpace(login)
				if login == "" {
					rl.SetPrompt("> ")
					continue
				}

				password, _ := rl.ReadPassword("Enter password: ")
				if string(strings.TrimSpace(string(password))) == "" {
					rl.SetPrompt("> ")
					continue
				}

				value = fmt.Sprintf(`{"username":"%s","password":"%s"}`, login, password)
			case "bank_card":
				rl.SetPrompt("Enter card number: ")
				cardNumber, _ := rl.Readline()
				rl.SetPrompt("Enter expiry date (MM/YY): ")
				expiryDate, _ := rl.Readline()
				cvv, _ := rl.ReadPassword("Enter CVV: ")

				if !validateBankCard(cardNumber, expiryDate, string(cvv)) {
					rl.SetPrompt("> ")
					continue
				}
				value = fmt.Sprintf(`{"card_number":"%s","expiry_date":"%s","cvv":"%s"}`, cardNumber, expiryDate, cvv)
			case "binary":
				rl.SetPrompt("Enter file path: ")
				filePath, _ := rl.Readline()

				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					fmt.Printf("File not found: %s\n", filePath)
					rl.SetPrompt("> ")
					continue
				}

				content, err := os.ReadFile(filePath)
				value = string(content)
				if err != nil {
					fmt.Printf("Error reading file: %v\n", err)
					return
				}
			default:
				rl.SetPrompt("Enter value: ")
				value, _ = rl.Readline()
			}

			rl.SetPrompt("Enter metadata: ")
			metadata, _ := rl.Readline()

			savePrivateData(key, value, dataType, metadata)
		case "delete":
			if !checkAuth() {
				continue
			}
			rl.SetPrompt("Enter key: ")
			key, _ := rl.Readline()

			deleteData(key)
		case "list":
			if !checkAuth() {
				continue
			}
			listData()
		case "help":
			printUsage()
		default:
			fmt.Println("Unknown command. Available commands: register, login, read, write, delete, list, help, exit")
			printUsage()
		}
		rl.SetPrompt("> ")
	}
}
