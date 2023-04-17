package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	fileName := "fileToEncrypt.txt"
	keyFileName := "key.txt"
	encryptedFileName := "encryptedFile.bin"

	// Open the file to be encrypted
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	// Read the key from a file
	key, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		log.Fatalf("failed reading key file: %s", err)
	}

	// Create the block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("failed creating block: %s", err)
	}

	// Choose a mode to encrypt the message
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("failed creating nonce: %s", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("failed creating AES GCM: %s", err)
	}

	// Open the destination file to write the encrypted data
	destFile, err := os.Create(encryptedFileName)
	if err != nil {
		log.Fatalf("failed creating destination file: %s", err)
	}
	defer destFile.Close()

	// Write the nonce to the destination file
	if _, err := destFile.Write(nonce); err != nil {
		log.Fatalf("failed writing nonce to destination file: %s", err)
	}

	// Encrypt the file by chunks
	bufferSize := 1024
	buffer := make([]byte, bufferSize)
	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("failed reading file: %s", err)
		}

		// Encrypt the block
		encryptedBlock := make([]byte, bufferSize+aesGCM.Overhead())
		aesGCM.Seal(encryptedBlock[:0], nonce, buffer[:bytesRead], nil)

		// Write the encrypted block to the destination file
		if _, err := destFile.Write(encryptedBlock); err != nil {
			log.Fatalf("failed writing encrypted block to destination file: %s", err)
		}
	}
}
