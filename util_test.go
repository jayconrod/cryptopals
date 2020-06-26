package main

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readHexFile(t *testing.T, path string) []byte {
	t.Helper()
	hdata := readFile(t, path)
	data := make([]byte, hex.DecodedLen(len(hdata)))
	if _, err := hex.Decode(data, hdata); err != nil {
		t.Fatalf("decoding hex %s: %v", path, err)
	}
	return data
}

func readBase64File(t *testing.T, path string) []byte {
	t.Helper()
	bdata := readFile(t, path)
	data := make([]byte, base64.StdEncoding.DecodedLen(len(bdata)))
	n, err := base64.StdEncoding.Decode(data, bdata)
	if err != nil {
		t.Fatalf("decoding base64 %s: %v", path, err)
	}
	data = data[:n]
	return data
}
