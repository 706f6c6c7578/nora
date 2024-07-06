package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

func generateNonce(r io.Reader, length int) (string, error) {
	b := make([]byte, length)
	if _, err := r.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func main() {
	lengthPtr := flag.Int("l", 16, "the length of the nonce")
	passwordPtr := flag.String("p", "", "the password")
	noncePtr := flag.Int("n", 1, "the number of nonces to be generated")
	savePtr := flag.Bool("s", false, "save nonces to files")
	partyBPtr := flag.Bool("b", false, "indicate if this is Party B")

	flag.Parse()

	if *passwordPtr == "" {
		fmt.Println("Usage: -p <password> [-b party B] [-n number of nonces] [-l length of the nonce] [-s save nonces]")
		return
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get current directory: %v\n", err)
		return
	}

	password := *passwordPtr
	date := time.Now().UTC().Format("20060102")
	hash := sha256.Sum256([]byte(password + date))

	if *partyBPtr {
		// Increment the hash by 1 if this is Party B
		for i := len(hash) - 1; i >= 0; i-- {
			hash[i]++
			if hash[i] != 0 {
				break
			}
		}
	}

	// Use HKDF to derive nonces
	hkdfReader := hkdf.New(sha256.New, hash[:], nil, nil)

	for i := 0; i < *noncePtr; i++ {
		value, err := generateNonce(hkdfReader, *lengthPtr)
		if err != nil {
			fmt.Printf("Failed to generate nonce: %v\n", err)
			return
		}
		fmt.Printf("%d: %s %s\n", i+1, value, date)

		if *savePtr {
			filename := fmt.Sprintf("n-%d", i+1)
			err := ioutil.WriteFile(filepath.Join(dir, filename), []byte(value), 0600)
			if err != nil {
				fmt.Printf("Failed to write nonce to file: %v\n", err)
			}
		}
	}
}

