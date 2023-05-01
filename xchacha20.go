package main

import (
	"fmt"
	"crypto/rand"
	"io"
	"log"
	"os"
    "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	memory      = 256 * 1024 // 64MB
	iterations  = 10
	parallelism = 4
	keyLen      = chacha20poly1305.KeySize
	saltLen     = 32
	nonceLen = 24
)

// GenerateKey generates an XChaCha20 key from a password using Argon2 key derivation
func GenerateKey(password string) ([]byte,[]byte, error) {
	// Generate a random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil,nil, err
	}

	// Generate the key using Argon2 key derivation
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)

	return key,salt, nil
}

func main() {
filedata, err := os.Open("plaintext.txt")
if err != nil {
	log.Fatal(err)
}
defer filedata.Close()

	// Create the output file
	outfile, err := os.Create("ciphertext.encrypted")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// Generate a random 24-byte nonce
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
password := "mysecretpassword"
	key,salt, err := GenerateKey(password)
	if err != nil {
		panic(err)
	}
fmt.Println(nonce , "-" , salt)
fmt.Println("key" , key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the file
	_, err = outfile.Write(nonce)
	if err != nil {
		log.Fatal(err)
	}
	_, err = outfile.Write([]byte("-"))
if err != nil {
    log.Fatal(err)
}
_, err = outfile.Write(salt)
if err != nil {
    log.Fatal(err)
}
buffer := make([]byte, 64*1024) // 64KB buffer
for {
	n, err := filedata.Read(buffer)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	if n == 0 {
		break
	}
	stream := aead.Seal(nil, nonce, buffer[:n], nil)
	_, err = outfile.Write(stream)
	if err != nil {
		log.Fatal(err)
	}
}
}
