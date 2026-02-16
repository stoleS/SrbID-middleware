package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

type ErrorResponse struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Details   string `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal JSON response",
			"error", err,
			"payload_type", fmt.Sprintf("%T", payload))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(response); err != nil {
		slog.Error("Failed to write response", "error", err)
	}
}

func RespondWithError(w http.ResponseWriter, code int, message string, details ...string) {
	errResponse := ErrorResponse{
		Code:    code,
		Message: message,
	}
	if len(details) > 0 {
		errResponse.Details = details[0]
	}
	RespondWithJSON(w, code, errResponse)
}

var (
	// RequestErrorHandler handles client request errors (4xx)
	RequestErrorHandler = func(w http.ResponseWriter, err error) {
		slog.Warn("Bad request", "error", err)
		RespondWithError(w, http.StatusBadRequest, err.Error())
	}
	// InternalErrorHandler handles internal server errors (5xx)
	InternalErrorHandler = func(w http.ResponseWriter, err error) {
		slog.Error("Internal server error", "error", err)
		RespondWithError(w, http.StatusInternalServerError, "An Unexpected Error has Occurred.")
	}
)
