package main

import (
	"log"
	"net"
)

func main() {
	_, err := net.ResolveUDPAddr("udp", ":3000")
	if err != nil {
		log.Fatal(err)
	}
}
