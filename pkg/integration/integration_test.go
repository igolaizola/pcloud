package integration

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/igolaizola/pcloud"
	"github.com/igolaizola/pcloud/pkg/crypto"
)

// Use `pcloud export` to generate key.pem
var privFile = "../../key.pem"

// Use `pcloud test-data` to generate enc_key.txt and enc_*.dat
var dataDir = "../../data"

func TestFile(t *testing.T) {
	priv, err := pcloud.LoadPrivateKey(privFile)
	if err != nil {
		t.Fatal(err)
	}
	encKeyData, err := ioutil.ReadFile(fmt.Sprintf("%s/enc_key.txt", dataDir))
	if err != nil {
		t.Fatal(err)
	}
	encKey := string(encKeyData)
	aesKey, hmacKey, err := crypto.DecryptKey(priv, encKey)
	if err != nil {
		t.Fatal(err)
	}

	var wants [][]byte
	var rnds []io.Reader
	i := 1
	for {
		want, err := ioutil.ReadFile(fmt.Sprintf("%s/enc_%03d.dat", dataDir, i))
		if err != nil {
			if i == 1 {
				t.Fatal(err)
			}
			break
		}
		wants = append(wants, want)
		rnds = append(rnds, toRandom(aesKey, want))
		i++
	}
	rnd := io.MultiReader(rnds...)

	plain, err := ioutil.ReadFile(fmt.Sprintf("%s/plain.dat", dataDir))
	if err != nil {
		t.Fatal(err)
	}

	// Test encrypt
	reader := crypto.Encrypt(rnd, aesKey, hmacKey, bytes.NewReader(plain), len(plain))
	for i := 0; i < len(wants); i++ {
		testBlock(t, i+1, reader, wants[i])
	}

	rest := make([]byte, 128)
	if nRest, err := reader.Read(rest); err != io.EOF {
		t.Errorf("wrong data length, extra: %d\n", nRest)
	}
}

func testBlock(t *testing.T, index int, reader io.Reader, want []byte) {
	got := make([]byte, crypto.EncryptBufferSize)
	n, err := reader.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Errorf("wrong data %d\nwant(%d): %x...\ngot(%d):  %x...\n", index, len(want), want[:32], n, got[:32])
	}
	for i := 0; i < n; i++ {
		if got[i] == want[i] {
			continue
		}
		t.Errorf("wrong data %d at %d\nwant: %x\ngot : %x\n", index, i, want[i:i+32], got[i:i+32])
		break
	}
	if n != len(want) {
		t.Errorf("wrong data %d length, missing: %d\n", index, len(want)-n)
	}
}

func toRandom(aesKey, enc []byte) io.Reader {
	var offset int
	switch {
	case len(enc) > 4096*128:
		offset = 4096 * 128
	case len(enc) > 4096:
		offset = len(enc) - 64
	case len(enc) > 32+16:
		offset = len(enc) - 32
	default:
		data := make([]byte, len(enc)-32)
		copy(data, enc[:len(enc)-32])
		curr := crypto.DecryptRandom(aesKey, enc[len(enc)-32:])
		data = append(data, curr[len(enc)-32:]...)
		return bytes.NewReader(data)
	}
	var data []byte
	for i := 0; i < 128; i++ {
		curr := crypto.DecryptRandom(aesKey, enc[offset:offset+32])
		data = append(data, curr...)
		offset += 32
		if offset+32 >= len(enc) {
			break
		}
	}
	return bytes.NewBuffer(data)
}
