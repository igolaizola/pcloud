package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/igolaizola/pcloud/pkg/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Launch command
	cmd := cli.NewCommand()
	if err := cmd.ParseAndRun(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
