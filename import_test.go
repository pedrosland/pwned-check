package pwned

import (
	"bytes"
	"reflect"
	"testing"
)

const testSavedFilter = ""

func TestReadPasswordList(t *testing.T) {
	contents := `df51e37c269aa94d38f93e537bf6e2020b21406c:12
0b6af663352ee0c8c74c90d4b20b6c7724b0547b:1
72eead6afcc03d99a3c0b5484f2aabedda1ba56e:1`
	filter := NewFilter(4, 4)

	reader := bytes.NewBufferString(contents)
	err := ReadPasswordList(filter, 3, reader)
	if err != nil {
		t.Errorf("error reading file: %s", err)
	}

	if count := filter.Count(); count != 3 {
		t.Errorf("got count %d, expected 3 hashes", count)
	}

	if found := filter.TestHash(mustDecode("72eead6afcc03d99a3c0b5484f2aabedda1ba56e")); !found {
		t.Error("filter does not contain hash")
	}
}

func TestLoadFilter(t *testing.T) {
	file := []byte{0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0xe2, 0x60, 0x14, 0xe2, 0xe3, 0xe2, 0x10, 0x60, 0x60, 0x60, 0x60, 0xe0, 0x60, 0x60, 0x10, 0x60, 0x94, 0x60, 0x2, 0x4, 0x0, 0x0, 0xff, 0xff, 0x3a, 0xc7, 0x15, 0xf1, 0x12, 0x0, 0x0, 0x0}
	buf := bytes.NewBuffer(file)

	f, err := LoadFilter(buf)
	if err != nil {
		t.Errorf("expected no error: %s", err)
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

	if count, expected := f.Count(), int64(2); count != expected {
		t.Errorf("got count %d, expected %d", count, expected)
	}
}

func TestSaveFilter(t *testing.T) {
	buf := &bytes.Buffer{}
	f := NewFilter(4, 2)
	f.AddHash(apple)
	f.AddHash(orange)

	_, err := SaveFilter(buf, f)
	if err != nil {
		t.Errorf("expected no error: %s", err)
	}

	expected := []byte{0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0xff, 0xe2, 0x60, 0x14, 0xe2, 0xe3, 0xe2, 0x10, 0x60, 0x60, 0x60, 0x60, 0xe0, 0x60, 0x60, 0x10, 0x60, 0x94, 0x60, 0x2, 0x4, 0x0, 0x0, 0xff, 0xff, 0x3a, 0xc7, 0x15, 0xf1, 0x12, 0x0, 0x0, 0x0}
	if !reflect.DeepEqual(buf.Bytes(), expected) {
		t.Errorf("got %#v, expected %#v", buf.Bytes(), expected)
	}
}
