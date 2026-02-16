package handlers

import (
	"net/http"
)

func noop(w http.ResponseWriter, r *http.Request) {}

func Handler(r *http.ServeMux) {
	r.HandleFunc("GET /status", noop)
	r.HandleFunc("GET /certificate", noop)
	r.HandleFunc("POST /sign", noop)
}
