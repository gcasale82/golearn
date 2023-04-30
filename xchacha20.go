package main

import (
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
)

// GenerateKey generates an XChaCha20 key from a password using Argon2 key derivation
func GenerateKey(password string) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Generate the key using Argon2 key derivation
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)

	return key, nil
}

func main() {
	// Open the file to encrypt
	//filein, err := os.Open("plaintext.txt")
	filedata,err := os.ReadFile("plaintext.txt")
	if err != nil {
		log.Fatal(err)
	}
	//defer filein.Close()

	// Create the output file
	outfile, err := os.Create("ciphertext.encrypted")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// Generate a random 24-byte nonce
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}
password := "mysecretpassword"
	key, err := GenerateKey(password)
	if err != nil {
		panic(err)
	}
	// Create the XChaCha20-Poly1305 cipher
	//key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the file
	_, err = outfile.Write(nonce)
	if err != nil {
		log.Fatal(err)
	}
	stream := aead.Seal(nil, nonce, filedata, nil)
	_, err = outfile.Write(stream)
	if err != nil {
		log.Fatal(err)
	}
}
