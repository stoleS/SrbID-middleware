package middleware

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

type withCodeWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *withCodeWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

		start := time.Now()

		withCode := &withCodeWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(withCode, r)

		logger.Info(
			"Request completed",
			slog.Int("status", withCode.statusCode),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Duration("duration", time.Since(start)),
		)
	})
}
