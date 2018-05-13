package main

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
