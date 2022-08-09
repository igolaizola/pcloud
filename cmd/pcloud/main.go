package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/igolaizola/pcloud"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := pcloud.Do(ctx); err != nil {
		log.Fatal(err)
	}
}
