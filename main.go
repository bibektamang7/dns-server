package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	fmt.Println("Logs from your program will appear here!")
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		log.Fatal(err)
		return
	}
	udpConn, err := net.ListenUDP("upd", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to addresss: ", err)
		return
	}

	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		response := []byte{}
		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response: ", err)
		}
	}
}
