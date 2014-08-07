package main

import (
	"kerberos"
	"log"
)

func main() {
	ctx, err := kerberos.NewContext()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Got %+v", *ctx)
	ctx.FreeContext()
}
