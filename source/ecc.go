package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"time"
	"io/ioutil"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func (key PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(key.D)
}

func (key PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(elliptic.Marshal(key.Curve, key.X, key.Y))
}

func PublicKeyFromString(public string) (*PublicKey, error) {
	publicKey, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, publicKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}
	return &PublicKey{
		Curve: curve,
		X:     x, Y: y,
	}, nil
}

func KeyFromString(private string) (*PrivateKey, error) {
	d, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(d)
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x, Y: y,
		},
		D: d,
	}, nil
}

func GenerateKey() (*PrivateKey, error) {
	curve := elliptic.P256()
	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func Encrypt(key crypto.PublicKey, data []byte) (encrypted []byte, err error) {
	if len(data) < 1 {
		err = errors.New("empty data")
		return
	}
	public := key.(*PublicKey)
	if public == nil {
		err = errors.New("invalid public key")
		return
	}
	private, err := GenerateKey()
	if err != nil {
		return
	}
	ephemeral := elliptic.Marshal(private.Curve, private.X, private.Y)
	sym, _ := public.Curve.ScalarMult(public.X, public.Y, private.D)
	// Create buffer
	buf := bytes.Buffer{}
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	hashed := sha256.Sum256(buf.Bytes())
	buf.Reset()
	block, err := aes.NewCipher(hashed[0:16])
	if err != nil {
		return
	}
	ch, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	_, err = buf.Write(ch.Seal(nil, hashed[16:], data, nil))
	if err != nil {
		return
	}
	encrypted = buf.Bytes()
	return
}

func Decrypt(key crypto.PrivateKey, data []byte) (decrypted []byte, err error) {
	if len(data) < 82 {
		err = errors.New("invalid data size")
		return
	}
	private := key.(*PrivateKey)
	if private == nil {
		err = errors.New("invalid private key")
		return
	}
	curve, buf := elliptic.P256(), bytes.Buffer{}
	x, y := elliptic.Unmarshal(curve, data[0:65])
	sym, _ := curve.ScalarMult(x, y, private.D)
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(data[0:65])
	if err != nil {
		return
	}
	hashed := sha256.Sum256(buf.Bytes())
	buf.Reset()

	block, err := aes.NewCipher(hashed[0:16])
	if err != nil {
		return
	}
	ch, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return
	}
	decrypted, err = ch.Open(nil, hashed[16:], data[65:], nil)
	return
}
func main()  {
        private, err := GenerateKey()
        if err != nil {
            panic(err.Error())
		}
		
		data, err := ioutil.ReadFile("test.txt")
   if err != nil {
       panic(err)
   }

   str := string(data)

		startTime := time.Now()
        encrypted, err := Encrypt(&private.PublicKey, []byte(str))
        if err != nil {
            panic(err.Error())
        }
		cost := time.Since(startTime)
	fmt.Printf("enc cost = [%s]\n", cost)


        fmt.Println("encrypted", encrypted, len(encrypted));
        // -> encrypted [4 13 13 236 218 227 ... 89] 86

		startTime = time.Now()
        decrypted, err := Decrypt(private, encrypted)
        if err != nil {
            panic(err.Error())
		}
		cost = time.Since(startTime)
	fmt.Printf("dec cost = [%s]\n", cost)

        fmt.Println("decrypted", decrypted, string(decrypted))
        // -> decrypted [104 101 108 108 111] hello
}