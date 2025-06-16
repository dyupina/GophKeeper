package main

import (
	"fmt"
	"net/http"

	"gophkeeper/internal/config"
	"gophkeeper/internal/handlers"
	"gophkeeper/internal/logger"
	"gophkeeper/internal/routing"
	"gophkeeper/internal/storage"
	"gophkeeper/internal/user"

	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"
)

func main() {
	sugarLogger, err := logger.NewLogger()
	if err != nil {
		sugarLogger.Fatalf("Failed to initialize logger: %v", err)
	}

	c := config.NewConfig()
	err = config.Init(c)
	if err != nil {
		sugarLogger.Fatalf("Failed to initialize config: %v", err)
	}

	fmt.Printf("c.DBConnection %s\n", c.DBConnection)

	s, err := storage.NewPostgresStorage(c.DBConnection)
	if err != nil {
		sugarLogger.Fatalf("Failed to connect to database: %v", err)
	}

	userService := user.NewUserService(s)

	ctrl := handlers.NewController(c, s, sugarLogger, userService)

	r := chi.NewRouter()

	routing.InitMiddleware(r, c, ctrl)
	routing.Routing(r, ctrl)

	server := routing.CreateServer(c, r, sugarLogger)

	// ротация MK каждые 3 дня
	cron := cron.New()
	_, err = cron.AddFunc("0 0 */3 * *", s.MasterKeyRotation)
	if err != nil {
		fmt.Println("Failed to schedule task:", err)
		return
	}
	cron.Start()
	defer cron.Stop()

	go func() {
		sugarLogger.Infof("Starting server on %s", c.Addr)
		if err := server.ListenAndServeTLS("https/localhost.crt", "https/localhost.key"); err != nil && err != http.ErrServerClosed {
			sugarLogger.Fatalf("Server failed: %v", err)
		}
	}()

	ctrl.HandleGracefulShutdown(server)
}
