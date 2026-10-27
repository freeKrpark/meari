package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/freekrpark/meari/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(server.NewMemoryStore()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("meari-server listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
