package pwned

// This borrows from Stefan Nilsson's great (real) Bloom filter.
// See https://github.com/yourbasic/bloom

import (
	"encoding/binary"
	"io"
	"math"

	pb "github.com/pedrosland/pwned-check/proto"
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

func (f Filter) getPB() *pb.State_Filter {
	return &pb.State_Filter{
		Count:   f.count,
		Lookups: int32(f.lookups),
		Size:    int64(len(f.data) * 8),
	}
}

func (f Filter) writeBytes(w io.Writer) (int, error) {
	b := make([]byte, 8, 8)

	for i := 0; i < len(f.data); i++ {
		binary.BigEndian.PutUint64(b, f.data[i])
		_, err := w.Write(b)
		if err != nil {
			return (i - 1) * 8, err
		}
	}
	return len(f.data) * 8, nil
}

func filterFrom(state *pb.State_Filter, r io.Reader) (*Filter, error) {
	data := make([]uint64, state.Size/8)
	b := make([]byte, 8, 8)

	for i := 0; i < len(data); i++ {
		_, err := r.Read(b)
		if err != nil && i < len(data)-1 {
			return nil, err
		}
		data[i] = binary.BigEndian.Uint64(b)
	}

	f := &Filter{
		count:   state.Count,
		data:    data,
		lookups: int(state.Lookups),
	}
	return f, nil
}
