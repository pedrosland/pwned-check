package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
)

func importFromFile(importPath string) {
	f, err := os.Open(importPath)
	if err != nil {
		log.Fatalf("error opening password hashes from %q: %s", importPath, err)
	}
	defer f.Close() // ignore error, we were only reading

	readPasswordFile(f)

	log.Printf("loaded %d hashed passwords from file %q", b.Count(), importPath)
}

func readPasswordFile(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// lines look like: 13c3d0d02ffc0e82abc1dd6b59d441be073d4b15:1
		line := strings.SplitN(scanner.Text(), ":", 2)
		hash, err := hex.DecodeString(line[0])
		if err != nil {
			log.Fatalf("error decoding hex string %q from password hash file: %s", line[0], err)
		}

		b.AddHash(hash)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading password hash file: %s", err)
	}
}

func loadFromFile(loadPath string) {
	f, err := os.Open(loadPath)
	if err != nil {
		log.Fatalf("error opening stored filter data from %q: %s", loadPath, err)
	}
	defer f.Close() // ignore error, we were only reading

	decoder := json.NewDecoder(f)
	data := jsonPwned{}
	err = decoder.Decode(&data)
	if err != nil {
		log.Fatalf("error reading stored filter data: %s", err)
	}

	log.Printf("loaded %d entries from %q", data.Filter.Count(), loadPath)

	b = data.Filter
}
