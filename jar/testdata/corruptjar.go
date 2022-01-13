package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"rsc.io/binaryregexp"
)

const (
	// Offset of compression field in LFH record.
	// See: https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
	lfhCompOffset = 0x8
	// Offset of compression field in CDH record.
	cdhCompOffset = 0xa
	// Reserved compression scheme.
	compReserved = 0xf
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprint(os.Stderr, "usage: go run corruptjar.go CLASS_TO_CORRUPT\n")
		os.Exit(1)
	}

	path := os.Args[1]

	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("ReadAll(Stdin) = %v", err)
	}

	lfh := binaryregexp.MustCompile(
		binaryregexp.QuoteMeta("PK\x03\x04") +
			`[\x00-\xff]{26}` +
			binaryregexp.QuoteMeta(path))

	m := lfh.FindIndex(b)
	if len(m) == 0 {
		log.Fatalf("Could not find %s Local File Header", path)
	}

	b[m[0]+lfhCompOffset] = compReserved

	cdh := binaryregexp.MustCompile(
		binaryregexp.QuoteMeta("PK\x01\x02") +
			`[\x00-\xff]{42}` +
			binaryregexp.QuoteMeta(path))

	m = cdh.FindIndex(b)
	if len(m) == 0 {
		log.Fatalf("Could not find %s Central Directory Header", path)
	}

	b[m[0]+cdhCompOffset] = compReserved

	if n, err := io.Copy(os.Stdout, bytes.NewBuffer(b)); err != nil || n != int64(len(b)) {
		log.Fatalf("Copy(Stdout, b) = %d, %v", n, err)
	}
}
