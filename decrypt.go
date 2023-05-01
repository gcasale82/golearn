package main

import (
	"io"
	"log"
	"os"
    "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"fmt"
)

const (
	memory      = 256 * 1024 // 64MB
	iterations  = 10
	parallelism = 4
	keyLen      = chacha20poly1305.KeySize
	saltLen     = 32
)


func ReadNonceAndSaltFromFile(filename string) ([]byte, []byte, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, nil, err
    }
    defer file.Close()

    // Read the nonce and salt
    nonceAndSalt := make([]byte, 24+saltLen+1)
    if _, err := io.ReadFull(file, nonceAndSalt); err != nil {
        return nil, nil, err
    }

    // Extract the nonce and salt
    nonce := nonceAndSalt[:24]
    salt := nonceAndSalt[25:]
	sep := nonceAndSalt[24]
    if sep != 45 {
        return nil, nil, fmt.Errorf("separator byte not found it is %v" , sep)
    }

    return nonce, salt, nil
}

func DecryptFile(password string, inputFile string, outputFile string) error {
    // Open the encrypted file for reading
    inFile, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer inFile.Close()
//var nonceAndSalt []byte
//nonceAndSalt, err = inFile.ReadN(24 + saltLen + 1) // read in 24-byte nonce, 32-byte salt, and 1-byte delimiter
var nonce []byte
var salt []byte
nonce , salt , err = ReadNonceAndSaltFromFile(inputFile)
fmt.Println(nonce , "-" , salt)
if err != nil {
    log.Fatal(err)
}
//nonce := nonceAndSalt[:24]
//salt := nonceAndSalt[25 : 25+saltLen]
key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
fmt.Println("key" , key)


aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        log.Fatal(err)
    }

    // Create a buffer to hold the decrypted data
    buffer := make([]byte, 0)

    // Decrypt the file in 64KB chunks
	if _, err := inFile.Seek(57, 0); err != nil {
    return err
}
    for {
        chunk := make([]byte, 64*1024)
        n, err := inFile.Read(chunk)
        if err != nil && err != io.EOF {
            log.Fatal(err)
        }
        if n == 0 {
            break
        }
        plaintext, err := aead.Open(nil, nonce, chunk[:n], nil)
        if err != nil {
			fmt.Printf("ciphertext len is %d" , len(chunk[:n]))
            log.Fatal(err)
        }
        buffer = append(buffer, plaintext...)
    }
 // Write the decrypted data to a new file
    outfile, err := os.Create(outputFile)
    if err != nil {
        log.Fatal(err)
    }
    defer outfile.Close()

    _, err = outfile.Write(buffer)
    if err != nil {
        log.Fatal(err)
    }
return err
}

func main(){
encfile := "ciphertext.encrypted"
decfile := "plaintext.txt"
mypass := "mysecretpassword"
err := DecryptFile(mypass,encfile , decfile)
if err != nil {
	fmt.Println("Error while decrypting")
}

}