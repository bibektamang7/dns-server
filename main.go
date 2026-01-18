package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

type Query struct {
	Header   Header
	Question Question
}

func (q *Query) Encode() []byte {
	headerBytes := q.Header.Encode()
	questionBytes := q.Question.Encode()
	return append(headerBytes, questionBytes...)
}

type Encoder interface {
	Encode() []byte
}

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

func (q *Question) Encode() []byte {
	var buf []byte

	for _, label := range strings.Split(q.Name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)

	qType := make([]byte, 2)
	qClass := make([]byte, 2)

	binary.BigEndian.PutUint16(qType, q.QType)
	binary.BigEndian.PutUint16(qClass, q.QClass)

	buf = append(buf, qType...)
	buf = append(buf, qClass...)

	return buf
}

type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *Header) Encode() []byte {
	var flags uint16
	if h.QR {
		flags |= 1 << 15
	}
	flags |= (uint16(h.Opcode) & 0xF) << 11
	if h.AA {
		flags |= 1 << 10
	}
	if h.TC {
		flags |= 1 << 9
	}
	if h.RD {
		flags |= 1 << 8
	}
	if h.RA {
		flags |= 1 << 7
	}
	flags |= (uint16(h.Z) & 0x7) << 4
	flags |= (uint16(h.RCode) & 0xF)

	buf := make([]byte, 12)

	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)

	return buf
}

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
		header := Header{
			ID:      1234,
			QR:      true,
			Opcode:  0,
			AA:      false,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCode:   0,
			QDCount: 1,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		}

		question := Question{
			Name:   "codecrafters.io",
			QType:  1,
			QClass: 1,
		}

		query := Query{
			Header:   header,
			Question: question,
		}

		response := query.Encode()

		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response: ", err)
		}
	}
}
