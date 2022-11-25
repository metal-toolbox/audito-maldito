package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln(err)
	}
}

func mainWithError() error {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalln("please specify a single file path to read")
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	counter := &readCounter{reader: f}

	scanner := bufio.NewScanner(counter)

	for scanner.Scan() {
	}

	if scanner.Err() != nil {
		return err
	}

	log.Printf("counter: %d", counter.count)

	current, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	log.Printf("seek: %d", current)

	return nil
}

type readCounter struct {
	reader io.Reader
	count  int64
}

func (o *readCounter) Read(p []byte) (int, error) {
	n, err := o.reader.Read(p)
	o.count += int64(n)
	return n, err
}
