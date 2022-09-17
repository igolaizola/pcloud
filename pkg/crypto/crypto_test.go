package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"testing"
)

func TestPrivateKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4092)
	if err != nil {
		t.Fatal(err)
	}
	want := x509.MarshalPKCS1PrivateKey(priv)
	pass := "P4ssw0rd!"
	key, err := EncryptPrivateKey(priv, pass)
	if err != nil {
		t.Fatal(err)
	}

	gotPriv, err := DecryptPrivateKey(key, pass)
	if err != nil {
		t.Fatal(err)
	}
	got := x509.MarshalPKCS1PrivateKey(gotPriv)
	if !bytes.Equal(got, want) {
		t.Errorf("got: %x\nwant: %x\n", got, want)
	}
}

func TestSymmetricKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4092)
	if err != nil {
		t.Fatal(err)
	}

	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 128)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		t.Fatal(err)
	}

	gotEncKey, err := EncryptKey(&priv.PublicKey, aesKey, hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	gotAesKey, gotHmacKey, err := DecryptKey(priv, gotEncKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aesKey, gotAesKey) {
		t.Errorf("aes key mismatch: expected %x, got %x", aesKey, gotAesKey)
	}
	if !bytes.Equal(hmacKey, gotHmacKey) {
		t.Errorf("hmac key mismatch: expected %x, got %x", hmacKey, gotHmacKey)
	}
}

func TestName(t *testing.T) {
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 128)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"short name": "helloworld.txt",
		// TODO(igolaizola): implement decrypt for long names
		// "long name":  "helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworld.txt",
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			want := test
			nameEnc, err := EncryptName(aesKey, hmacKey, want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecryptName(aesKey, hmacKey, nameEnc)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("got: %s\nwant: %s\n", got, want)
			}
		})
	}
}

func TestEncryptFile(t *testing.T) {
	tests := map[string]struct {
		size     int
		wants    []string
		wantSize int
	}{
		"very small": {
			size: 250,
			wants: []string{
				"0a6041cccdfbc25b31c96a772e498ac80f6940545d7543443a6c5304d21986a6",
			},
			wantSize: 282,
		},
		"small": {
			size: 1000,
			wants: []string{
				"cc13fdeff91be0abccd558bad55f69db7c788dabedeaa9f6cee61f04a39785e7",
			},
			wantSize: 1032,
		},
		"medium": {
			size: 9529,
			wants: []string{
				"99a74911a339f265e22d0cacc12c154c03a8d8d34d8084750295432e72208b95",
			},
			wantSize: 9657,
		},
		"large": {
			size: 1042592,
			wants: []string{
				"a5876d09964edbad7074d30bbb9b94536211d47bc833af692662677714a49462",
				"6b42e14b115098bf71a82a5f82b1998d96f889444091b43a968deea4f9789339",
			},
			wantSize: 1050848,
		},
		"large, exact 2 blocks": {
			size: 4096 * 128 * 2,
			wants: []string{
				"33783f4497e9f87864b6ea4c8b8488e456101891751fab51d66b1d11c67d54b2",
				"a91d66de59bcb98236eba2e1eef38c9e101a1e6284270d4df200cd6faa09e5b6",
			},
			wantSize: 1056864,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			rnd := mrand.New(mrand.NewSource(int64(test.size)))
			input := make([]byte, test.size)
			if _, err := io.ReadFull(rnd, input); err != nil {
				t.Fatal(err)
			}
			_ = ioutil.WriteFile(fmt.Sprintf("../../data/%d/%d.txt", test.size, test.size), input, 0644)
			aesKey, hmacKey, err := GenerateKey(rnd)
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, EncryptBufferSize)
			reader := Encrypt(rnd, aesKey, hmacKey, bytes.NewReader(input), len(input))

			i := 0
			gotSize := 0
			for {
				n, err := reader.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				gotSize += n
				if i >= len(test.wants) {
					t.Fatalf("got more data than expected: %d", i+1)
				}

				want := fromHex(test.wants[i])
				got := sha256.Sum256(buf[:n])

				if !bytes.Equal(got[:], want) {
					t.Errorf("got: %x\nwant: %x\n", got, want)
				}
				i++
			}
			if gotSize != test.wantSize {
				t.Errorf("invalid size, got: %d, want: %d", gotSize, test.wantSize)
			}
		})
	}
}
func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
