package pwned

//go:generate rm -rf $PWD/proto/
//go:generate mkdir $PWD/proto/
//go:generate protoc -I=$PWD --go_out=proto $PWD/filter.proto

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/golang/protobuf/proto"
	pb "github.com/pedrosland/pwned-check/proto"
)

const fileVersion = 1

// ImportPasswordFile opens a file and loads the passwords into the given filter
func ImportPasswordFile(filter *Filter, numHashes int64, importPath string) {
	var f io.ReadCloser
	var err error

	if importPath == "-" {
		log.Println("importing password hashes from stdin")

		f = os.Stdin
	} else {
		log.Printf("importing password hashes from file %s", importPath)

		f, err = os.Open(importPath)
		if err != nil {
			log.Fatalf("error opening password hashes: %s", err)
		}
		defer f.Close() // ignore error, we were only reading
	}

	err = ReadPasswordList(filter, numHashes, f)
	if err != nil {
		log.Fatalf("error processing password hash file: %s", err)
	}

	log.Printf("loaded %d hashed passwords from file %s", filter.Count(), importPath)
}

// ReadPasswordList reads from a reader and loads its password hashes into the filter
func ReadPasswordList(filter *Filter, numHashes int64, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	hash := make([]byte, 20)
	var err error
	for scanner.Scan() {
		if filter.count >= numHashes {
			return fmt.Errorf("filter full: tried to add %d passwords but capacity is %d", filter.count+1, numHashes)
		}

		// lines look like: 13c3d0d02ffc0e82abc1dd6b59d441be073d4b15:123
		line := scanner.Bytes()
		index := bytes.IndexRune(line, ':')
		_, err = hex.Decode(hash, line[:index])
		if err != nil {
			return fmt.Errorf("error decoding hex string %q: %s", []byte(line), err)
		}

		filter.AddHash(hash)
	}
	return err
}

// LoadFilterFromFile reads a saved Filter from file and returns it.
func LoadFilterFromFile(loadPath string) *Filter {
	log.Printf("loading filter from file %s", loadPath)

	f, err := os.Open(loadPath)
	if err != nil {
		log.Fatalf("error opening stored filter data from %q: %s", loadPath, err)
	}
	defer f.Close() // ignore error, we were only reading

	filter, err := LoadFilter(f)
	if err != nil {
		log.Printf("error loading filter: %s", err)
	}

	log.Printf("loaded %d entries from %s", filter.Count(), loadPath)

	return filter
}

// LoadFilter reads a Filter from a reader and returns it.
func LoadFilter(r io.Reader) (*Filter, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %s", err)
	}
	defer gz.Close() // ignore error

	bytes, err := ioutil.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("decompres file: %s", err)
	}

	state := &pb.State{}
	err = proto.Unmarshal(bytes, state)
	if err != nil {
		return nil, fmt.Errorf("decode state: %s", err)
	}

	// nolint - allow memory to be freed as early as possible
	bytes = nil

	return filterFromPB(state.Filter), nil
}

// SaveFilterToFile saves the given filter to file
func SaveFilterToFile(filter *Filter, savePath string) {
	f, err := os.Create(savePath)
	if err != nil {
		log.Fatalf("error opening data file to write: %s", err)
		return
	}

	size, err := SaveFilter(f, filter)
	if err != nil {
		log.Fatalf("error saving filter: %s", err)
	}

	err = f.Close()
	if err != nil {
		log.Fatalf("error closing file: %s", err)
		return
	}

	log.Printf("filter saved (%d uncompressed bytes)", size)
}

// SaveFilter writes the given filter to the writer.
// It will destroy the filter while this is happening.
func SaveFilter(w io.Writer, filter *Filter) (int, error) {
	state := &pb.State{
		Filter:  filter.getPB(),
		Version: fileVersion,
	}

	// release the old filter as soon as we can
	*filter = *NewFilter(2, 2)

	bytes, err := proto.Marshal(state)
	if err != nil {
		return 0, fmt.Errorf("encode state: %s", err)
	}

	// nolint - allow to free memory as soon as possible
	state = nil

	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return 0, fmt.Errorf("create gzip writer: %s", err)
	}

	size, err := gz.Write(bytes)
	if err != nil {
		return 0, fmt.Errorf("compress data: %s", err)
	}

	err = gz.Close()
	if err != nil {
		return 0, fmt.Errorf("close gz writer: %s", err)
	}

	return size, nil
}
