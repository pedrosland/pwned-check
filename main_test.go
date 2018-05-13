package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/AndreasBriese/bbloom"
	dataence "github.com/dataence/bloom/standard"
	yourbasic "github.com/yourbasic/bloom"
)

var wordlist1 [][]byte
var wordlist2 []uint64

const n = 1.0 << 19
const p = 10000

func TestMain(m *testing.M) {
	file, err := os.Open("words.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	wordlist1 = make([][]byte, n)
	wordlist2 = make([]uint64, n)
	for i := range wordlist1 {
		if scanner.Scan() {
			wordlist1[i] = []byte(scanner.Text())
			hash, err := hex.DecodeString(scanner.Text())
			if err != nil {
				panic(err)
			}
			wordlist2[i] = binary.BigEndian.Uint64(hash)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n###############\nbbloom_test.go")
	fmt.Printf("Benchmarks relate to ?? OP. --> output/%d op/ns\n###############\n\n", len(wordlist1))

	// fmt.Printf("Yourbasic false positive rate: %.10f\n", yourbasic.New(n, p).EstimateFalsePositiveRate(500000*p))
	// fmt.Printf("Yourbasic false positive rate: %.10f\n", yourbasic.New(n, p).EstimateFalsePositiveRateHash(500000*p))

	m.Run()
}

func BenchmarkYourbasic(b *testing.B) {
	bf := yourbasic.New(n, p)

	for i := range wordlist1 {
		bf.AddByte(wordlist1[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for i := range wordlist1 {
			bf.TestByte(wordlist1[i])
		}
	}
}

func BenchmarkYourbasicNoHash(b *testing.B) {
	bf := yourbasic.New(n, p)

	for i := range wordlist2 {
		bf.AddHash(wordlist2[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for i := range wordlist2 {
			bf.TestHash(wordlist2[i])
		}
	}
}

func BenchmarkBbloom(b *testing.B) {
	// this filter offers json output

	// bf := bbloom.New(n, 1/p)
	bf := bbloom.New(n, 0.0001)

	for i := range wordlist1 {
		bf.Add(wordlist1[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for i := range wordlist1 {
			bf.Has(wordlist1[i])
		}
	}
}

func BenchmarkDataence(b *testing.B) {
	bf := dataence.New(n)

	for i := range wordlist1 {
		bf.Add(wordlist1[i])
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for i := range wordlist1 {
			bf.Check(wordlist1[i])
		}
	}
}

func BenchmarkLeveldb(b *testing.B) {
	bf := NewFilter(nil, wordlist1, p/10)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for i := range wordlist1 {
			bf.MayContain(wordlist1[i])
		}
	}
}

// type H struct {
// 	item []byte
// }

// func (h *H) Write(b []byte) (int, error) {
// 	h.item = b
// 	panic(len(b))
// 	return len(b), nil
// }

// func (h *H) BlockSize() int {
// 	return 1
// }

// func (h *H) Size() int {
// 	return 160
// }

// func (h *H) Sum(b []byte) []byte {
// 	s := append(b, h.item...)
// 	return s
// }

// func (h *H) Reset() {
// }

// func BenchmarkDataenceHasher(b *testing.B) {
// 	bf := dataence.New(n)
// 	h := new(H)
// 	bf.SetHasher(h)

// 	for i := range wordlist2 {
// 		bf.Add(binary.BigEndian.(wordlist2[i]))
// 	}

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		for i := range wordlist2 {
// 			bf.Check(wordlist2[i])
// 		}
// 	}
// }
