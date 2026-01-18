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
	Answers  []ResourceRecord
}

func (q *Query) Encode() []byte {
	headerBytes := q.Header.Encode()
	questionBytes := q.Question.Encode()
	answerBytes := []byte{}
	for _, ans := range q.Answers {
		answerBytes = append(answerBytes, ans.Encode()...)
	}
	hq := append(headerBytes, questionBytes...)
	return append(hq, answerBytes...)
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

func (rr *ResourceRecord) Encode() []byte {
	var buf []byte
	for _, label := range strings.Split(rr.Name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, 0x00)

	t := make([]byte, 2)
	binary.BigEndian.PutUint16(t, rr.Type)
	buf = append(buf, t...)

	c := make([]byte, 2)
	binary.BigEndian.PutUint16(c, rr.Class)
	buf = append(buf, c...)

	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, rr.TTL)
	buf = append(buf, ttl...)

	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(rr.RData)))
	buf = append(buf, rdlen...)

	buf = append(buf, rr.RData...)

	return buf
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

type Message struct {
	Header      *Header
	Questions   []*Question
	Answers     []*ResourceRecord
	Authorities []*ResourceRecord
	Additionals []*ResourceRecord
}

func ParseMessage(data []byte) (*Message, error) {
	h, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	return &Message{}, nil
}

type parser struct {
	data []byte
	off  int
}

func (p *parser) readByte() byte {
	b := p.data[p.off]
	p.off++
	return b
}

func (p *parser) readUint16() uint16 {
	v := binary.BigEndian.Uint16(p.data[p.off:])
	p.off += 2
	return v
}

func (p *parser) readUint32() uint32 {
	v := binary.BigEndian.Uint32(p.data[p.off:])
	p.off += 4
	return v
}

func parseHeader(data []byte) (*Header, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("too short for DNS header")
	}

	h := &Header{}
	h.ID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	h.QR = (flags>>15)&1 == 1
	h.Opcode = uint8((flags >> 11) & 0xF)
	h.AA = (flags>>10)&1 == 1
	h.TC = (flags>>9)&1 == 1
	h.RD = (flags>>8)&1 == 1
	h.RA = (flags>>7)&1 == 1
	h.Z = uint8((flags >> 4) & 0x7)
	h.RCode = uint8(flags & 0xF)

	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])

	return h, nil
}

func (p *parser) readQuestion() (*Question, error) {
	name, err := p.readName()
	if err != nil {
		return nil, err
	}

	return &Question{
		Name:   name,
		QType:  p.readUint16(),
		QClass: p.readUint16(),
	}, nil

}

func (p *parser) readResourceRecord() (*ResourceRecord, error) {
	name, err := p.readName()
	if err != nil {
		return nil, err
	}

	rr := &ResourceRecord{
		Name:  name,
		Type:  p.readUint16(),
		Class: p.readUint16(),
		TTL:   p.readUint32(),
	}

	rdlen := p.readUint16()

	if p.off+int(rdlen) > len(p.data) {
		return nil, fmt.Errorf("truncated rdata")
	}

	rr.RData = p.data[p.off : p.off+int(rdlen)]
	p.off += int(rdlen)
	return rr, nil
}

func (p *parser) readName() (string, error) {
	var labels []string

	start := p.off
	jumped := false

	for {
		if p.off >= len(p.data) {
			return "", fmt.Errorf("name out of range")
		}
		length := int(p.data[p.off])
		p.off++

		if length&0xC0 == 0xC0 {
			if p.off >= len(p.data) {
				return "", fmt.Errorf("truncated pointer")
			}
			ptr := ((length & 0x3F) << 8) | int(p.data[p.off])
			p.off++

			sub := &parser{data: p.data, off: ptr}
			name, err := sub.readName()
			if err != nil {
				return "", err
			}
			labels = append(labels, name)

			if !jumped {
				start = p.off
			}
			jumped = true
			break
		}
		if length == 0 {
			break // terminator case
		}

		if p.off+length > len(p.data) {
			return "", fmt.Errorf("truncate label")
		}
		label := string(p.data[p.off : p.off+length])
		p.off += length
		labels = append(labels, label)
	}

	if jumped {
		p.off = start
	}

	return strings.Join(labels, "."), nil

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

		message, err := ParseMessage(buf[:size])
		var responseCode uint8 = 0

		if message.Header.Opcode != 0 {
			responseCode = 4
		}

		header := Header{
			ID:      message.Header.ID,
			QR:      true,
			Opcode:  message.Header.Opcode,
			AA:      false,
			TC:      false,
			RD:      message.Header.RD,
			RA:      false,
			Z:       0,
			RCode:   message.Header.RCode,
			QDCount: 1,
			ANCount: 1,
			NSCount: 0,
			ARCount: 0,
		}

		answer := ResourceRecord{
			Name:  "codecrafters.io",
			Type:  1,
			Class: 1,
			TTL:   60,
			RData: []byte{8, 8, 8, 8},
		}

		question := Question{
			Name:   "codecrafters.io",
			QType:  1,
			QClass: 1,
		}

		query := Query{
			Header:   header,
			Question: question,
			Answers:  []ResourceRecord{answer},
		}

		response := query.Encode()

		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response: ", err)
		}
	}
}
