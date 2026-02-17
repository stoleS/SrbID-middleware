package certificate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/stoleS/SrbID-middleware/api"
	"github.com/stoleS/SrbID-middleware/internal/tools"
)

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details"`
}

type StatusResponse struct {
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
	Version            int    `json:"version"`
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
		cardStatus, err := cm.GetStatus()
		if err != nil {
			api.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}

		api.RespondWithJSON(w, http.StatusOK, StatusResponse{
			ReaderConnected: cardStatus.ReaderConnected,
			CardPresent:     cardStatus.CardPresent,
			TokenLabel:      cardStatus.TokenLabel,
		})
	}
}

func GetCertificate(cm *tools.CardManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		derBytes, cert, err := cm.GetSigningCertificate()
		if err != nil {
			httpStatus, code, message := tools.MapPKCS11Error(err)
			api.RespondWithError(w, httpStatus, code, message)
			return
		}

		resp := CertificateResponse{
			Certificate: base64.StdEncoding.EncodeToString(derBytes),
		}

		if cert != nil {
			resp.Subject = cert.Subject.String()
			resp.Signature = base64.StdEncoding.EncodeToString(cert.Signature)
			resp.Issuer = cert.Issuer.String()
			resp.ValidFrom = cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
			resp.ValidTo = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
			resp.Serial = fmt.Sprintf("%X", cert.SerialNumber)
			resp.Version = cert.Version
			resp.SignatureAlgorithm = cert.SignatureAlgorithm.String()
			resp.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
		}

		api.RespondWithJSON(w, http.StatusOK, resp)
	}
}

func (req *SignRequest) Validate(allowedAlgorithms map[string]bool) error {
	req.PIN = strings.TrimSpace(req.PIN)

	if len(req.PIN) < 4 || len(req.PIN) > 8 {
		return fmt.Errorf("PIN must be 4-8 characters long")
	}

	if req.Algorithm == "" {
		return fmt.Errorf("algorithm is required (use SHA-1, SHA-256, SHA-384, or SHA-512)")
	}

	if !allowedAlgorithms[req.Algorithm] {
		return fmt.Errorf("unsupported algorithm: %s (use SHA-1, SHA-256, SHA-384, or SHA-512)", req.Algorithm)
	}

	if req.Hash == "" {
		return fmt.Errorf("hash is required")
	}

	hashBytes, err := base64.StdEncoding.DecodeString(req.Hash)
	if err != nil {
		return fmt.Errorf("invalid base64 hash")
	}

	if len(hashBytes) != tools.HashLengths[req.Algorithm] {
		return fmt.Errorf("invalid hash length for %s: got %d bytes, expected %d",
			req.Algorithm, len(hashBytes), tools.HashLengths[req.Algorithm])
	}

	return nil
}

func CertificateSign(cm *tools.CardManager) http.HandlerFunc {
	allowedAlgorithms := map[string]bool{
		"SHA-1": true, "SHA-256": true, "SHA-384": true, "SHA-512": true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var req SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			var unmarshalErr *json.UnmarshalTypeError
			if errors.As(err, &unmarshalErr) {
				api.RequestErrorHandler(w, fmt.Errorf("field '%s' must be a %s", unmarshalErr.Field, unmarshalErr.Type))
				return
			}
			api.RequestErrorHandler(w, fmt.Errorf("invalid request body"))
			return
		}

		if err := req.Validate(allowedAlgorithms); err != nil {
			api.RequestErrorHandler(w, err)
			return
		}

		hashBytes, _ := base64.StdEncoding.DecodeString(req.Hash)

		signature, err := cm.Sign(req.PIN, hashBytes, req.Algorithm)
		if err != nil {
			httpStatus, code, message := tools.MapPKCS11Error(err)
			api.RespondWithError(w, httpStatus, message, code)
			return
		}

		api.RespondWithJSON(w, http.StatusOK, SignResponse{
			Signature: base64.StdEncoding.EncodeToString(signature),
		})
	}
}
