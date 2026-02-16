package handlers

import (
	"net/http"

	"github.com/stoleS/SrbID-middleware/internal/handlers/certificate"
)

func Handler(r *http.ServeMux) {
	r.HandleFunc("GET /status", certificate.GetCertificateStatus)
	r.HandleFunc("GET /certificate", certificate.GetCertificate)
	r.HandleFunc("POST /sign", certificate.WithCertificateSign)
}
