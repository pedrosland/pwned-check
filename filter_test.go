package main

import (
	"encoding/json"
	"testing"
)

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

func TestFilterJSON(t *testing.T) {
	f := NewFilter(4, 2)
	f.AddHash(apple)
	f.AddHash(orange)

	bytes, err := json.Marshal(&f)
	if err != nil {
		t.Errorf("unexpected error marshalling filter: %s", err)
	}

	f = NewFilter(8, 1)
	err = json.Unmarshal(bytes, f)
	if err != nil {
		t.Errorf("unexpected error unmarshalling filter: %s", err)
	}

	if count := f.Count(); count != 2 {
		t.Errorf("got count %d, expected 2", count)
	}
	if lookups := f.lookups; f.lookups != 1 {
		t.Errorf("got lookups %d, expected 1", lookups)
	}

	if found := f.TestHash(apple); !found {
		t.Errorf("found no apple, expected apple")
	}
	if found := f.TestHash(orange); !found {
		t.Errorf("found no orange, expected orange")
	}
	if found := f.TestHash(pear); found {
		t.Errorf("found pear, expected no pear")
	}
}
