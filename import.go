package pwned

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type jsonPwned struct {
	Version string  `json:"version"`
	Filter  *Filter `json:"filter"`
}

// ImportPasswordFile opens a file and loads the passwords into the given filter
func ImportPasswordFile(filter *Filter, numHashes int64, importPath string) {
	log.Printf("importing password hashes from file %s", importPath)

	f, err := os.Open(importPath)
	if err != nil {
		log.Fatalf("error opening password hashes: %s", err)
	}
	defer f.Close() // ignore error, we were only reading

	err = readPasswordList(filter, numHashes, f)
	if err != nil {
		log.Fatalf("error processing password hash file: %s", err)
	}

	log.Printf("loaded %d hashed passwords from file %s", filter.Count(), importPath)
}

// readPasswordList reads from a reader and loads its password hashes into the filter
func readPasswordList(filter *Filter, numHashes int64, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if count := filter.Count(); count >= numHashes {
			return fmt.Errorf("filter full: tried to add %d passwords but capacity is %d", count+1, numHashes)
		}

		// lines look like: 13c3d0d02ffc0e82abc1dd6b59d441be073d4b15:123
		line := strings.SplitN(scanner.Text(), ":", 2)
		hash, err := hex.DecodeString(line[0])
		if err != nil {
			return fmt.Errorf("error decoding hex string %q: %s", line[0], err)
		}

		filter.AddHash(hash)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// LoadFilterFromFile reads a saved filter from file and returns it
func LoadFilterFromFile(loadPath string) *Filter {
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

	log.Printf("loaded %d entries from %s", data.Filter.Count(), loadPath)

	return data.Filter
}

// SaveFilterToFile saves the given filter to file
func SaveFilterToFile(filter *Filter, version string, savePath string) {
	f, err := os.Create("pwned-data.json")
	if err != nil {
		log.Fatalf("error opening data file to write: %s", err)
		return
	}

	data := jsonPwned{
		Filter:  filter,
		Version: version,
	}

	encoder := json.NewEncoder(f)
	err = encoder.Encode(&data)
	if err != nil {
		log.Fatalf("error writing data to file: %s", err)
	}

	err = f.Close()
	if err != nil {
		log.Fatalf("error closing file: %s", err)
		return
	}

	log.Println("filter saved")
}
