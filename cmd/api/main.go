package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/stoleS/SrbID-middleware/internal/handlers"
	"github.com/stoleS/SrbID-middleware/internal/middleware"
	"github.com/stoleS/SrbID-middleware/internal/tools"
)

func main() {
	cfg, err := tools.LoadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	router := http.NewServeMux()
	handlers.Handler(router)

	stack := middleware.CreateStack(middleware.Logging)

	server := http.Server{
		Addr:         cfg.Addr(),
		Handler:      stack(router),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	logger := slog.Default()

	logger.Info("Server starting", slog.String("addr", server.Addr), slog.String("origins", fmt.Sprintf("%v", cfg.AllowedOrigins)))

	if err := server.ListenAndServe(); err != nil {
		logger.Error("There was a problem starting the server", "error", err)
		os.Exit(1)
	}

	logger.Info("Server started successfully")
}
