package main

import (
	"log"
	"net/http"

	"github.com/stoleS/SrbID-middleware/internal/handlers"
)

func main() {
	router := http.NewServeMux()
	handlers.Handler(router)

	server := http.Server{
		Addr:    ":9889",
		Handler: router,
	}

	err := server.ListenAndServe()

	log.Printf("Listening on port 9889")

	if err != nil {
		log.Fatal(err)
	}
}
