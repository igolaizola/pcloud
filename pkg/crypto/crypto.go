package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"

	aesecb "github.com/andreburgaud/crypt2go/ecb"
	"golang.org/x/crypto/pbkdf2"
)

func GenerateKey(rnd io.Reader) ([]byte, []byte, error) {
	aesKey := make([]byte, 32)
	_, err := io.ReadFull(rnd, aesKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't generate key: %w", err)
	}
	hmacKey := make([]byte, 160-32)
	_, err = io.ReadFull(rnd, hmacKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't generate key: %w", err)
	}
	return aesKey, hmacKey, nil
}

func DecryptPrivateKey(encPriv, pass string) (*rsa.PrivateKey, error) {
	encPrivBytes, err := base64.RawURLEncoding.DecodeString(encPriv)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't decode private key: %w", err)
	}
	saltLength := 64
	salt := encPrivBytes[8 : saltLength+8]
	privCipher := encPrivBytes[saltLength+8:]

	passBytes := []byte(pass)
	derived := pbkdf2.Key(passBytes, salt, 20000, 48, sha512.New)

	aesKey := derived[:32]
	nonce := derived[32:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't create cipher: %w", err)
	}
	privBytes := decryptAESCTR(block, privCipher, nonce)
	privBytes = privBytes[:len(privBytes)-4]

	privRSA, err := x509.ParsePKCS1PrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("pcloud: couldn't parse private key: %w", err)
	}
	return privRSA, nil
}

func EncryptPrivateKey(priv *rsa.PrivateKey, pass string) (string, error) {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privBytes = append(privBytes, 0, 0, 0, 0)

	salt := make([]byte, 64)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pcloud: couldn't generate salt: %w", err)
	}

	passBytes := []byte(pass)
	derived := pbkdf2.Key(passBytes, salt, 20000, 48, sha512.New)

	aesKey := derived[:32]
	nonce := derived[32:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("pcloud: couldn't create cipher: %w", err)
	}
	privCipher := encryptAESCTR(block, privBytes, nonce)

	encPrivBytes := make([]byte, 8+len(salt)+len(privCipher))
	binary.BigEndian.PutUint64(encPrivBytes, 0)
	copy(encPrivBytes[8:], salt)
	copy(encPrivBytes[8+len(salt):], privCipher)

	return base64.RawURLEncoding.EncodeToString(encPrivBytes), nil
}

func DecryptKey(priv *rsa.PrivateKey, encKey string) ([]byte, []byte, error) {
	encKeyBytes, err := base64.RawURLEncoding.DecodeString(encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't decode encoded key: %w", err)
	}

	keyBytes, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, encKeyBytes, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't decrypt key: %w", err)
	}
	keyBytes = keyBytes[8:]
	aesKey := keyBytes[:32]
	hmacKey := keyBytes[32:]
	return aesKey, hmacKey, nil
}

func EncryptKey(pub *rsa.PublicKey, aesKey, hmacKey []byte) (string, error) {
	keyBytes := make([]byte, 8+len(aesKey)+len(hmacKey))
	copy(keyBytes[8:], aesKey)
	copy(keyBytes[8+len(aesKey):], hmacKey)
	encKeyBytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, keyBytes, nil)
	if err != nil {
		return "", fmt.Errorf("pcloud: couldn't encrypt key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encKeyBytes), nil
}

func EncryptName(aesKey, hmacKey []byte, name string) (string, error) {
	nameEncBytes := make([]byte, 16)
	copy(nameEncBytes, []byte(name))
	nameEncBytes = encryptAESECB(xor(nameEncBytes, hmacKey), aesKey)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b32 := base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	nameEnc := b32.EncodeToString(nameEncBytes)
	return nameEnc, nil
}

func DecryptName(aesKey, hmacKey []byte, nameEnc string) (string, error) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b32 := base32.NewEncoding(alphabet).WithPadding(base32.NoPadding)
	nameEncBytes, err := b32.DecodeString(nameEnc)
	if err != nil {
		return "", fmt.Errorf("pcloud: couldn't decode name: %w", err)
	}
	if len(nameEncBytes) != 16 {
		lastEnc := nameEncBytes[16:]
		firstEnc := nameEncBytes[:16]
		last := decryptAESCBC(lastEnc, aesKey, firstEnc)
		last = bytes.TrimRight(last, "\x00")
		h := hmac.New(sha512.New, hmacKey)
		if _, err := h.Write(last); err != nil {
			return "", fmt.Errorf("pcloud: couldn't write to hmac: %w", err)
		}
		sha := h.Sum(nil)
		first := decryptAESCBC(firstEnc, aesKey, sha[:16])
		first = bytes.TrimRight(first, "\x00")
		return string(append(first, last...)), nil
	}

	nameBytes := xor(decryptAESECB(nameEncBytes, aesKey), hmacKey)
	nameBytes = bytes.TrimRight(nameBytes, "\x00")
	return string(nameBytes), nil
}

func DecryptRandom(aesKey, cipheredAuth []byte) []byte {
	auth := decryptAESECB(cipheredAuth, aesKey)
	rnd := make([]byte, 16)
	copy(rnd, auth[:8])
	copy(rnd[8:], auth[24:])
	return rnd
}

func DecryptData(aesKey, hmacKey []byte, cipheredData, cipheredAuth []byte, index int) ([]byte, error) {
	auth := decryptAESECB(cipheredAuth, aesKey)

	iv := make([]byte, 16)
	copy(iv, auth[8:24])
	rnd := make([]byte, 16)
	copy(rnd, auth[:8])
	copy(rnd[8:], auth[24:])

	var output []byte
	forHMAC := make([]byte, len(cipheredData)+8+16)
	if len(cipheredData) < 16 {
		output = xor(cipheredData, rnd)
		copy(forHMAC, output)
		copy(forHMAC[len(output):], uint64toBytes(uint64(index)))
		copy(forHMAC[len(output)+8:], rnd)
	} else {
		md16 := len(cipheredData) % 16
		n := len(cipheredData) - md16 - 16
		forCBC := cipheredData[:n]
		forMix := cipheredData[n:]

		fromCBC := decryptAESCBC(forCBC, aesKey, iv)

		mixIV := cipheredData[n-16 : n]
		tmp := decryptAESECB(forMix[:16], aesKey)
		last := xor(tmp[0:md16], forMix[16:])

		forMixCBC := append(forMix[16:], tmp[md16:]...)
		lastBlock := decryptAESCBC(forMixCBC, aesKey, mixIV)
		fromMIX := append(lastBlock, last...)

		output = append(fromCBC, fromMIX...)
		copy(forHMAC, output)
		copy(forHMAC[len(output):], uint64toBytes(uint64(index)))
		copy(forHMAC[len(output)+8:], rnd)
	}

	h := hmac.New(sha512.New, hmacKey)
	if _, err := h.Write(forHMAC); err != nil {
		return nil, fmt.Errorf("pcloud: couldn't write to hmac: %w", err)
	}
	sha := h.Sum(nil)

	if !bytes.Equal(sha[0:16], iv) {
		return nil, fmt.Errorf("pcloud: hmac mismatch")
	}

	return output, nil
}

const EncryptBufferSize = 4096 * 130

func Encrypt(rnd io.Reader, aesKey, hmacKey []byte, input io.Reader, size int) io.Reader {
	rd, wr := io.Pipe()
	go func() {
		if err := encrypt(rnd, aesKey, hmacKey, input, size, wr); err != nil {
			wr.CloseWithError(err)
			return
		}
		_ = wr.Close()
	}()
	return rd
}

func encrypt(rnd io.Reader, aesKey, hmacKey []byte, input io.Reader, size int, wr io.Writer) error {
	buf := make([]byte, 4096*128)
	i := 0

	authLevel := 1
	t := int(math.Trunc((float64(size) + 4096 - 1) / 4096))
	t = int(math.Trunc((float64(t) + 128 - 1) / 128))
	for t > 1 {
		t = int(math.Trunc((float64(t) + 128 - 1) / 128))
		authLevel++
	}

	sectors := int(math.Ceil(float64(size-32) / float64(4096*128)))

	auth := make([][]byte, 7)
	authcnt := make([]int, 7)
	var blockData, blockAuth []byte
	for {
		n, err := input.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("pcloud: couldn't read file: %w", err)
		}
		curr := make([]byte, n)
		copy(curr, buf[:n])
		blockData, blockAuth, err = EncryptBlock(rnd, aesKey, hmacKey, curr, i)
		if err != nil {
			return err
		}
		blockData = append(blockData, blockAuth...)
		signed := sign(aesKey, hmacKey, blockAuth)
		auth[0] = append(auth[0], signed...)
		authcnt[0]++

		if size > 4096 {
			for j := 0; j < authLevel; j++ {
				if authcnt[j] == 128 || (i == sectors-1 && authcnt[j] > 0) {
					new := make([]byte, len(auth[j]))
					copy(new, auth[j])
					blockData = append(blockData, new...)
					signed := sign(aesKey, hmacKey, auth[j])
					auth[j+1] = append(auth[j+1], signed...)
					authcnt[j+1]++
					auth[j] = nil
					authcnt[j] = 0
				}
			}
		}
		if wr.Write(blockData); err != nil {
			return fmt.Errorf("pcloud: couldn't write to pipe: %w", err)
		}
		i++
	}
	return nil
}

func EncryptBlock(rnd io.Reader, aesKey, hmacKey, plain []byte, index int) ([]byte, []byte, error) {
	var auth []byte
	var data []byte
	sectorIndex := index * 128
	for i := 0; i < len(plain); i += 4096 {
		n := i + 4096
		if n > len(plain) {
			n = len(plain)
		}
		curr := make([]byte, n-i)
		copy(curr, plain[i:n])
		currData, currAuth, err := EncryptSector(rnd, aesKey, hmacKey, curr, sectorIndex)
		if err != nil {
			return nil, nil, fmt.Errorf("pcloud: couldn't encrypt data: %w", err)
		}
		data = append(data, currData...)
		auth = append(auth, currAuth...)
		sectorIndex++
	}
	return data, auth, nil
}

func EncryptSector(rnd io.Reader, aesKey, hmacKey, plain []byte, index int) ([]byte, []byte, error) {
	rndBytes := make([]byte, 16)
	if _, err := io.ReadFull(rnd, rndBytes); err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't read random bytes: %w", err)
	}

	forHMAC := append(plain, uint64toBytes(uint64(index))...)
	forHMAC = append(forHMAC, rndBytes...)
	h := hmac.New(sha512.New, hmacKey)
	if _, err := h.Write(forHMAC); err != nil {
		return nil, nil, fmt.Errorf("pcloud: couldn't write to hmac: %w", err)
	}
	iv := h.Sum(nil)[:16]

	if len(plain) < 16 {
		cipheredData := make([]byte, len(plain))
		copy(cipheredData, rndBytes[:len(plain)])
		forXOR := make([]byte, 16)
		copy(forXOR, xor(rndBytes, plain))
		copy(forXOR[len(plain):], rndBytes[len(plain):])

		auth := make([]byte, 32)
		copy(auth, forXOR[:8])
		copy(auth[8:], iv)
		copy(auth[24:], forXOR[8:])
		cipheredAuth := encryptAESECB(auth, aesKey)[:32]

		return cipheredData, cipheredAuth, nil
	}

	auth := make([]byte, 32)
	copy(auth, rndBytes[:8])
	copy(auth[8:], iv)
	copy(auth[24:], rndBytes[8:])

	cipheredAuth := encryptAESECB(auth, aesKey)[:32]
	md16 := len(plain) % 16
	n := len(plain)
	if md16 > 0 {
		n = len(plain) - md16 - 16
	}
	forCBC := make([]byte, n)
	copy(forCBC, plain[:n])
	forMix := make([]byte, len(plain)-n)
	copy(forMix, plain[n:])

	var fromCBC []byte
	if len(forCBC) > 0 {
		fromCBC = encryptAESCBC(forCBC, aesKey, iv)
	}
	var fromMix []byte
	if len(forMix) > 0 {
		mixIV := iv
		if len(fromCBC) > 0 {
			mixIV = fromCBC[len(fromCBC)-16:]
		}
		tmp := encryptAESCBC(forMix[:16], aesKey, mixIV)
		last := tmp[:md16]
		forAESECB := append(xor(forMix[16:16+md16], tmp), tmp[md16:]...)
		lastBlock := encryptAESECB(forAESECB, aesKey)
		fromMix = append(lastBlock, last...)
	}
	cipheredData := append(fromCBC, fromMix...)
	return cipheredData, cipheredAuth, nil
}

func sign(aesKey, hmacKey, data []byte) []byte {
	forHMAC := make([]byte, len(data))
	copy(forHMAC, data)
	h := hmac.New(sha512.New, hmacKey)
	if _, err := h.Write(forHMAC); err != nil {
		panic(err)
	}
	s := h.Sum(nil)[:32]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err.Error())
	}
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(s, s)
	return s

}

func SHA1(input string) string {
	sum := sha1.Sum([]byte(input))
	return hex.EncodeToString(sum[:])
}

func encryptAESECB(pt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := aesecb.NewECBEncrypter(block)
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func decryptAESECB(ct, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := aesecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	return pt
}

func decryptAESCBC(ct, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	return pt
}

func encryptAESCBC(pt, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func decryptAESCTR(aes cipher.Block, input []byte, iv []byte) []byte {
	var output []byte
	var h int32
	for n := 0; n < len(input); n += len(iv) {
		f0 := swapInt32(h)
		f := []int32{f0, 0, 0, 0}
		fBytes := toBytes(f)

		enc := make([]byte, len(fBytes))
		aes.Encrypt(enc, xor(fBytes, iv))
		ln := n + len(iv)
		if ln > len(input) {
			ln = len(input)
		}
		u := xor(enc, input[n:ln])
		output = append(output, u...)
		h++
	}
	return output
}

func encryptAESCTR(aes cipher.Block, input []byte, iv []byte) []byte {
	return decryptAESCTR(aes, input, iv)
}

func xor(a []byte, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	c := make([]byte, n)
	for i := 0; i < n; i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func swapInt32(input int32) int32 {
	v := toBytes([]int32{input})
	b0 := v[0]
	b1 := v[1]
	b2 := v[2]
	b3 := v[3]
	return toInt32s([]byte{b3, b2, b1, b0})[0]
}

func toInt32s(v []byte) []int32 {
	var ints []int32
	for i := 0; i < len(v); i += 4 {
		ints = append(ints, int32(v[i])<<24|int32(v[i+1])<<16|int32(v[i+2])<<8|int32(v[i+3]))
	}
	return ints
}

func toBytes(v []int32) []byte {
	var b []byte
	for _, i := range v {
		b = append(b, byte(i>>24))
		b = append(b, byte(i>>16))
		b = append(b, byte(i>>8))
		b = append(b, byte(i))
	}
	return b
}

func uint64toBytes(i uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, i)
	return b
}
