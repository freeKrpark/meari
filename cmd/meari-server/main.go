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
	wipe := flag.Bool("wipe", true, "overwrite delivered messages in memory; turn off only to measure the difference")
	flag.Parse()

	store := server.NewMemoryStore()
	store.WipeOnAck = *wipe

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(store),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("meari-server listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
