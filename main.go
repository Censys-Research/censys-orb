package main

import (
	"log"

	"github.com/censys-research/censys-orb/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
