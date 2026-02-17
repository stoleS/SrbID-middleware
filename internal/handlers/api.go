package handlers

import (
	"net/http"

	"github.com/stoleS/SrbID-middleware/api"
	"github.com/stoleS/SrbID-middleware/internal/handlers/certificate"
	"github.com/stoleS/SrbID-middleware/internal/tools"
)

type HealthResponse struct {
	Status string `json:"status"`
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	api.RespondWithJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func Handler(r *http.ServeMux, cm *tools.CardManager) {
	r.HandleFunc("/health", HealthCheck)

	r.HandleFunc("GET /v1/status", certificate.GetCertificateStatus(cm))
	r.HandleFunc("GET /v1/certificate", certificate.GetCertificate(cm))
	r.HandleFunc("POST /v1/sign", certificate.CertificateSign(cm))
}
