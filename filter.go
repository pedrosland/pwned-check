package pwned

// This borrows from Stefan Nilsson's great (real) Bloom filter.
// See https://github.com/yourbasic/bloom

import (
	"encoding/binary"
	"encoding/json"
	"math"
)

const (
	shift = 6
	mask  = 0x3f
)

// Filter represents a kind-of-Bloom filter.
type Filter struct {
	data    []uint64 // Bit array, the length is a power of 2.
	lookups int      // Lookups per query
	count   int64    // Estimate number of elements
}

// NewFilter creates an empty kind-of-Bloom filter with room for n elements
// at a false-positive rate less than 1/p.
// It is kind-of because it doesn't actully hash the data itself but
// assumes that data is already hashed.
func NewFilter(n int, p int) *Filter {
	minWords := int(0.0325 * math.Log(float64(p)) * float64(n))
	words := 1
	for words < minWords {
		words *= 2
	}
	return &Filter{
		data:    make([]uint64, words),
		lookups: int(1.4*math.Log(float64(p)) + 1),
	}
}

// AddHash adds s to the filter and tells if s was already a likely member.
func (f *Filter) AddHash(b []byte) bool {
	// yes, we are losing data here
	h1 := binary.BigEndian.Uint64(b[0:8]) + uint64(binary.BigEndian.Uint32(b[8:12]))
	h2 := binary.BigEndian.Uint64(b[12:])

	trunc := uint64(len(f.data))<<shift - 1
	member := true
	for i := f.lookups; i > 0; i-- {
		h1 += h2
		n := h1 & trunc
		k, b := n>>shift, uint64(1<<uint(n&mask))
		if f.data[k]&b == 0 {
			member = false
			f.data[k] |= b
		}
	}
	if !member {
		f.count++
	}
	return member
}

// TestHash tells if s is a likely member of the filter.
// If true, s is probably a member; if false, s is definitely not a member.
func (f *Filter) TestHash(b []byte) bool {
	h1 := binary.BigEndian.Uint64(b[0:8]) + uint64(binary.BigEndian.Uint32(b[8:12]))
	h2 := binary.BigEndian.Uint64(b[12:])

	trunc := uint64(len(f.data))<<shift - 1
	for i := f.lookups; i > 0; i-- {
		h1 += h2
		n := h1 & trunc
		k, b := n>>shift, uint64(1<<uint(n&mask))
		if f.data[k]&b == 0 {
			return false
		}
	}
	return true
}

// Count returns an estimate of the number of elements in the filter.
func (f *Filter) Count() int64 {
	return f.count
}

type jsonFilter struct {
	Data    []uint64 `json:"data"`
	Lookups int      `json:"lookups"`
	Count   int64    `json:"count"`
}

// MarshalJSON returns a []byte containing the JSON representation of the filter
func (f Filter) MarshalJSON() ([]byte, error) {
	jf := jsonFilter{
		Data:    f.data,
		Lookups: f.lookups,
		Count:   f.count,
	}

	return json.Marshal(&jf)
}

// UnmarshalJSON takes a []byte and populates the filter with its state
func (f *Filter) UnmarshalJSON(b []byte) error {
	jf := jsonFilter{}
	err := json.Unmarshal(b, &jf)
	if err != nil {
		return err
	}

	f.data = jf.Data
	f.lookups = jf.Lookups
	f.count = jf.Count

	return nil
}
