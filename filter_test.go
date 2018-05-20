package pwned

import (
	"encoding/hex"
	"testing"
)

var apple []byte
var orange []byte
var pear []byte

func TestMain(m *testing.M) {
	apple = mustDecode("d0be2dc421be4fcd0172e5afceea3970e2f3d940")
	orange = mustDecode("ef0ebbb77298e1fbd81f756a4efc35b977c93dae")
	pear = mustDecode("3e2bf5faa2c3fec1f84068a073b7e51d7ad44a35")

	m.Run()
}

func mustDecode(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}

func TestFilter(t *testing.T) {
	f := NewFilter(4, 4)
	if found := f.TestHash(apple); found {
		t.Error("found apple, expected no apple")
	}
	if found := f.AddHash(apple); found {
		t.Error("found apple when adding hash, expected no apple")
	}
	if found := f.TestHash(apple); !found {
		t.Error("found no apple, expected apple")
	}

	if found := f.TestHash(orange); found {
		t.Error("found orange, expected no orange")
	}
	if found := f.AddHash(orange); found {
		t.Error("found orange when adding hash, expected no orange")
	}
	if found := f.TestHash(orange); !found {
		t.Error("found no orange, expected orange")
	}

	if count, expected := f.Count(), int64(2); count != expected {
		t.Errorf("got count of %d, expected %d", count, expected)
	}
}

// func TestFilterJSON(t *testing.T) {
// 	f := NewFilter(4, 2)
// 	f.AddHash(apple)
// 	f.AddHash(orange)

// 	bytes, err := json.Marshal(&f)
// 	if err != nil {
// 		t.Errorf("unexpected error marshalling filter: %s", err)
// 	}

// 	f = NewFilter(8, 1)
// 	err = json.Unmarshal(bytes, f)
// 	if err != nil {
// 		t.Errorf("unexpected error unmarshalling filter: %s", err)
// 	}

// 	if count := f.Count(); count != 2 {
// 		t.Errorf("got count %d, expected 2", count)
// 	}
// 	if lookups := f.lookups; f.lookups != 1 {
// 		t.Errorf("got lookups %d, expected 1", lookups)
// 	}

// 	if found := f.TestHash(apple); !found {
// 		t.Errorf("found no apple, expected apple")
// 	}
// 	if found := f.TestHash(orange); !found {
// 		t.Errorf("found no orange, expected orange")
// 	}
// 	if found := f.TestHash(pear); found {
// 		t.Errorf("found pear, expected no pear")
// 	}
// }

func TestPB(t *testing.T) {
	f := NewFilter(4, 2)
	f.AddHash(apple)
	f.AddHash(orange)

	f2 := filterFromPB(f.getPB())

	if found := f.TestHash(apple); !found {
		t.Errorf("found no apple, expected apple")
	}
	if found := f.TestHash(orange); !found {
		t.Errorf("found no orange, expected orange")
	}
	if found := f.TestHash(pear); found {
		t.Errorf("found pear, expected no pear")
	}

	if c1, c2 := f.Count(), f2.Count(); c1 != c2 {
		t.Errorf("got count %d, expected %d", c2, c1)
	}
}
