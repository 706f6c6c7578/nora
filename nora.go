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
	"golang.org/x/crypto/pbkdf2"
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
	saltPtr := flag.String("salt", "", "the salt for PBKDF2")

	flag.Parse()

	if *passwordPtr == "" {
		fmt.Println("Usage: -p <password> [-salt <salt>] [-b party B] [-n number of nonces] [-l length of the nonce] [-s save nonces]")
		return
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Failed to get current directory: %v\n", err)
		return
	}

	password := *passwordPtr
	date := time.Now().UTC().Format("20060102")

	var key []byte
	if *saltPtr != "" {
		// Use PBKDF2 with salt and date
		iterations := 10000 // You can adjust this number
		combinedSalt := []byte(*saltPtr + date)
		key = pbkdf2.Key([]byte(password), combinedSalt, iterations, 32, sha256.New)
	} else {
		// Keep the old method if no salt is provided
		hash := sha256.Sum256([]byte(password + date))
		key = hash[:]
	}

	if *partyBPtr {
		// Increment the key by 1 if this is Party B
		for i := len(key) - 1; i >= 0; i-- {
			key[i]++
			if key[i] != 0 {
				break
			}
		}
	}

	// Use HKDF to derive nonces
	hkdfReader := hkdf.New(sha256.New, key, nil, nil)

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