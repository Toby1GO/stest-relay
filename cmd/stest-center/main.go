package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"socks5-go/internal/center"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := center.Run(ctx, os.Args[1:]); e != nil {
		log.Fatal(e)
	}
}
