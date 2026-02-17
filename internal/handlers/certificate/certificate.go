package certificate

import (
	"net/http"

	"github.com/stoleS/SrbID-middleware/internal/tools"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details"`
}

type StatusResponse struct {
	Status          string `json:"status"`
	ReaderConnected bool   `json:"reader_connected"`
	CardPresent     bool   `json:"card_present"`
	TokenLabel      string `json:"token_label"`
}

// CertificateResponse List of available fields can be seen here https://pkg.go.dev/crypto/x509#Certificate
type CertificateResponse struct {
	Certificate        string `json:"certificate"`
	Signature          string `json:"signature"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	ValidFrom          string `json:"valid_from"`
	ValidTo            string `json:"valid_to"`
	Serial             string `json:"serial_number"`
	Version            string `json:"version"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

type SignRequest struct {
	PIN       string `json:"pin"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

type SignResponse struct {
	Signature string `json:"signature"`
}

func GetCertificateStatus(cm *tools.CardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}
}

func GetCertificate(cm *tools.CardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}
}

func CertificateSign(cm *tools.CardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}
}
