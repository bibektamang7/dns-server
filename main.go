package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

type Query struct {
	Header    Header
	Questions []*Question
	Answers   []*ResourceRecord
}

func (q *Query) Encode() []byte {
	buf := []byte{}
	headerBytes := q.Header.Encode()
	buf = append(buf, headerBytes...)

	offsetMap := map[string]int{}

	for _, question := range q.Questions {
		question.Encode(&buf, offsetMap)
	}
	for _, ans := range q.Answers {
		ans.Encode(&buf, offsetMap)
	}
	return buf
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

func (rr *ResourceRecord) Encode(buf *[]byte, offsetMap map[string]int) {
	encodeName(rr.Name, buf, offsetMap)

	tmp := make([]byte, 10)
	binary.BigEndian.PutUint16(tmp[0:2], rr.Type)
	binary.BigEndian.PutUint16(tmp[2:4], rr.Class)
	binary.BigEndian.PutUint32(tmp[4:8], rr.TTL)
	binary.BigEndian.PutUint16(tmp[8:10], uint16(len(rr.RData)))

	*buf = append(*buf, tmp...)
	*buf = append(*buf, rr.RData...)
}

type Encoder interface {
	Encode() []byte
}

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

func encodeName(name string, buf *[]byte, offsetMap map[string]int) {
	if name == "" {
		*buf = append(*buf, 0)
		return
	}

	labels := strings.Split(name, ".")
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if pos, ok := offsetMap[suffix]; ok {
			pointer := 0xC000 | pos
			p := make([]byte, 2)
			binary.BigEndian.PutUint16(p, uint16(pointer))
			*buf = append(*buf, p...)
			return
		}

		offsetMap[suffix] = len(*buf)
		label := labels[i]

		*buf = append(*buf, byte(len(label)))
		*buf = append(*buf, []byte(label)...)
	}

	*buf = append(*buf, 0)
}

func (q *Question) Encode(buf *[]byte, offsetMap map[string]int) {

	encodeName(q.Name, buf, offsetMap)

	qType := make([]byte, 2)
	qClass := make([]byte, 2)

	binary.BigEndian.PutUint16(qType, q.QType)
	binary.BigEndian.PutUint16(qClass, q.QClass)

	*buf = append(*buf, qType...)
	*buf = append(*buf, qClass...)

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
	p := &parser{data: data, off: 12}
	m := &Message{Header: h}

	for i := 0; i < int(h.QDCount); i++ {
		q, err := p.readQuestion()
		if err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}

	for i := 0; i < int(h.ANCount); i++ {
		rr, err := p.readResourceRecord()
		if err != nil {
			return nil, err
		}
		m.Answers = append(m.Answers, rr)
	}

	for i := 0; i < int(h.NSCount); i++ {
		rr, err := p.readResourceRecord()
		if err != nil {
			return nil, err
		}
		m.Authorities = append(m.Authorities, rr)
	}
	for i := 0; i < int(h.ARCount); i++ {
		rr, err := p.readResourceRecord()
		if err != nil {
			return nil, err
		}
		m.Additionals = append(m.Additionals, rr)
	}

	return m, nil
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
	return p.readNameWithJumps(make(map[int]bool))
}

func (p *parser) readNameWithJumps(visited map[int]bool) (string, error) {
	var labels []string

	originalOff := p.off // for the sake of compression!

	jumped := false // track if we've followed a pointer

	for {
		if p.off >= len(p.data) {
			return "", fmt.Errorf("name out of range")
		}

		if visited[p.off] {
			return "", fmt.Errorf("compression loop detected at offset %d", p.off)
		}
		length := int(p.data[p.off])
		p.off++

		if length&0xC0 == 0xC0 {
			if p.off >= len(p.data) {
				return "", fmt.Errorf("truncated pointer")
			}
			ptr := ((length & 0x3F) << 8) | int(p.data[p.off])
			p.off++

			if ptr >= len(p.data) {
				return "", fmt.Errorf("pointer out of range %d", ptr)
			}

			visited[originalOff] = true

			sub := &parser{data: p.data, off: ptr}
			name, err := sub.readNameWithJumps(visited)
			if err != nil {
				return "", err
			}

			if name != "" {
				labels = append(labels, name)
			}

			if !jumped {
				jumped = true // mark that we've followed a pointer
			}
			break //compression pointer always terminates current label sequence
		}

		if length > 63 {
			return "", fmt.Errorf("label too long %d", length)
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

	return strings.Join(labels, "."), nil

}

func answerQuestion(q *Question) *ResourceRecord {
	return &ResourceRecord{
		Name:  q.Name,
		Type:  1,
		Class: 1,
		TTL:   60,
		RData: []byte{8, 8, 8, 8},
	}
}

func main() {
	fmt.Println("Logs from your program will appear here!")
	addr := flag.String("resolver", "", "The address of DNS resolver to use")

	flag.Parse()

	resAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		fmt.Println("failed to resolve resolver address UDP")
		return
	}

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
		if err != nil {
			fmt.Println("something went wrong parsing message, %w", err)
		}

		var responseCode uint8 = 0

		if message.Header.Opcode != 0 {
			responseCode = 4
		}

		if resAddr != nil && responseCode == 0 {
			var allAnswers []*ResourceRecord

			for _, question := range message.Questions {
				singleQuery := Query{
					Header: Header{
						ID:      message.Header.ID,
						QR:      false,
						Opcode:  message.Header.Opcode,
						AA:      false,
						TC:      false,
						RD:      message.Header.RD,
						RA:      false,
						Z:       0,
						RCode:   0,
						QDCount: 1,
						ANCount: 0,
						NSCount: 0,
						ARCount: 0,
					},
					Questions: []*Question{question},
					Answers:   []*ResourceRecord{},
				}
				quryData := singleQuery.Encode()

				conn, err := net.DialUDP("udp", nil, resAddr)
				if err != nil {
					fmt.Println("failed to dial resolver")
				}

				_, err = conn.Write(quryData)
				if err != nil {
					fmt.Println("unable to send query to resolver")
					conn.Close()
					continue
				}

				responseData := make([]byte, 512)
				n, err := conn.Read(responseData)

				conn.Close()
				if err != nil {
					fmt.Println("failed to read from connection")
					continue
				}

				ressolverResponse , err := ParseMessage(responseData[:n])
				if err != nil {
					fmt.Println("failed to parse messsage")
					continue
				}

				allAnswers = append(allAnswers, ressolverResponse.Answers...)

			}

			finalResponse := Query {
				Header: Header{
					ID: message.Header.ID,
					QR: true,
					Opcode: message.Header.Opcode,
					AA: false,
					TC: false, 
					RD: message.Header.RD,
					RA: true,
					Z:0,
					RCode: 0,
					QDCount: uint16(len(message.Questions)),
					ANCount: uint16(len(allAnswers)),
					NSCount: 0,
					ARCount: 0,
				},
				Questions: message.Questions,
				Answers: allAnswers,
			}
			responseBytes := finalResponse.Encode()
			_, err := udpConn.WriteToUDP(responseBytes, source)

			if err != nil {
				fmt.Println("failed to write response to source")
			}
			continue
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
			RCode:   responseCode,
			QDCount: uint16(len(message.Questions)),
			ANCount: uint16(len(message.Questions)),
			NSCount: 0,
			ARCount: 0,
		}

		// 	Name:  message.Questions[0].Name,
		// 	Type:  1,
		// 	Class: 1,
		// 	TTL:   60,
		// 	RData: []byte{8, 8, 8, 8},
		// }
		//
		// question := Question{
		// 	Name:   message.Questions[0].Name,
		// 	QType:  1,
		// 	QClass: 1,
		// }

		answers := []*ResourceRecord{}
		for _, question := range message.Questions {
			answer := answerQuestion(question)
			answers = append(answers, answer)
		}

		query := Query{
			Header:    header,
			Questions: message.Questions,
			Answers:   answers,
		}

		response := query.Encode()

		_, err = udpConn.WriteToUDP(response, source)

		if err != nil {
			fmt.Println("Failed to send response: ", err)
		}
	}
}
