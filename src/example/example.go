package main

import (
	"kerberos"
	"log"
)

const ipname = "user@EXAMPLE.COM"

func main() {
	ctx, err := kerberos.NewContext(false)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer ctx.Free()
	log.Printf("Context: %+v", *ctx)

	princ, err := ctx.NewPrincipal(ipname)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer ctx.FreePrincipal(princ)
	log.Printf("Principal: %+v", *princ)

	opname, err := ctx.Unparse(princ)
	log.Printf("Unparse: %s", opname)

	if ipname != opname {
		log.Printf("%+v != %+v!", ipname, opname)
	}

	lname, err := ctx.Localname(princ)
	log.Printf("Localname: %s", lname)
}
