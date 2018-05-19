package pwned

import (
	"bytes"
	"testing"
)

func TestReadPasswordList(t *testing.T) {
	contents := `df51e37c269aa94d38f93e537bf6e2020b21406c:12
0b6af663352ee0c8c74c90d4b20b6c7724b0547b:1
72eead6afcc03d99a3c0b5484f2aabedda1ba56e:1`
	filter := NewFilter(4, 4)

	reader := bytes.NewBufferString(contents)
	err := readPasswordList(filter, 3, reader)
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
