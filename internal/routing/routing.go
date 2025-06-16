package routing

import (
	"gophkeeper/internal/config"
	"gophkeeper/internal/handlers"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func InitMiddleware(r *chi.Mux, conf *config.Config, ctrl *handlers.Controller) {
	r.Use(ctrl.PanicRecoveryMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(ctrl.AuthenticateMiddleware)
}

func Routing(r *chi.Mux, ctrl *handlers.Controller) {
	r.Post("/register", ctrl.Register())
	r.Post("/login", ctrl.Login())
	r.Post("/save", ctrl.SavePrivateData())
	r.Post("/get", ctrl.GetPrivateData())
	r.Post("/delete", ctrl.DeletePrivateData())
	r.Get("/list", ctrl.ListPrivateData())
	r.Get("/ping", ctrl.Ping())

}

func CreateServer(c *config.Config, handler http.Handler, logger *zap.SugaredLogger) *http.Server {
	return &http.Server{
		Addr:              c.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 20 * time.Second,
	}
}
