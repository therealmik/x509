package main

import (
	"encoding/json"
	"bufio"
	"github.com/therealmik/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var csv = flag.Bool("csv", false, "Data is in csv format")
var csvColumn = flag.Int("column", 1, "CSV column (0 is first)")

func main() {
	log.SetOutput(os.Stderr)
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("No files specified")
	}

	ch := make(chan []byte)

	go printCertificates(ch)
	for _, filename := range flag.Args() {
		log.Print("Loading certificates from ", filename)
		if *csv {
			readCsv(filename, ch)
		} else {
			readPem(filename, ch)
		}
	}
}

func readPem(filename string, ch chan<- []byte) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		ch <- block.Bytes
	}
}

func readCsv(filename string, ch chan<- []byte) {
	fd, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	if *csvColumn < 0 {
		log.Fatal("Invalid CSV column")
	}

	scanner := bufio.NewScanner(fd)
	var lineNumber int
	for scanner.Scan() {
		lineNumber += 1
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) < (*csvColumn - 1) {
			log.Fatalf("Malformed line in %s:%d (should be exactly 1 comma per line), got %v", filename, lineNumber, fields)
		}
		data, err := base64.StdEncoding.DecodeString(fields[*csvColumn])
		if err != nil {
			log.Fatalf("Malformed base64 in %s:%d: %v", filename, lineNumber, err)
		}
		ch <- data
	}
}

func printCertificates(ch <-chan []byte) {
	for blob := range ch {
		cert, err := x509.ParseCertificate(blob)
		if err != nil {
			log.Printf("Error in cert %v: %s", err, base64.StdEncoding.EncodeToString(blob))
			continue
		}
		b, err := json.Marshal(cert)
		if err != nil {
			log.Panic(err)
		}
		b = append(b, 0xa)
		os.Stdout.Write(b)
	}
}
