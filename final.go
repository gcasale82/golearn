package main
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"errors"
	"regexp"
	"golang.org/x/crypto/ssh/terminal"
	"crypto/rand"
	"io"
	"log"
    "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"path/filepath"
	"time"
)

const (
	memory      = 256 * 1024 // 64MB
	iterations  = 10
	parallelism = 4
	keyLen      = chacha20poly1305.KeySize
	saltLen     = 32
	nonceLen = 24
)
func search(fileString string) ([]string  ,error) {
output ,err := exec.Command("find", fileString, "-type", "f").Output()
if err != nil {
	emptySlice := make([]string, 0)
		return emptySlice, errors.New("file not found !")
	}
files := strings.Split(string(output), "\n")
return files , nil

}

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

func EncryptFile(password string , filename string) {
	filedata, err := os.Open(filename)
if err != nil {
	log.Fatal(err)
}
defer filedata.Close()
isFullPath := filepath.IsAbs(filename)
if isFullPath {
	filename = filepath.Base(filename)
}
    suffix := ".encrypted"
    now := time.Now()
    formattedDate := now.Format("02-01-2006-15-04-05") // DD-MM-YYYY-HH-MM-SS
    encFileName := filename + "-" + formattedDate + suffix
	// Create the output file
	outfile, err := os.Create(encFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	// Generate a random 24-byte nonce
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
    key,salt, err := GenerateKey(password)
	if err != nil {
		panic(err)
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
func DecryptFile(password string , inputFile string) error {
    // Open the encrypted file for reading
    inFile, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer inFile.Close()
var nonce []byte
var salt []byte
nonce , salt , err = ReadNonceAndSaltFromFile(inputFile)
if err != nil {
    log.Fatal(err)
}
key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLen)
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
            log.Fatal(err)
        }
        buffer = append(buffer, plaintext...)
    }
	isFullPath := filepath.IsAbs(inputFile)
if isFullPath {
	inputFile = filepath.Base(inputFile)
}
    suffix := ".encrypted"
    regEnd := strings.HasSuffix(inputFile, suffix)
	var outputFile string
    if regEnd {
		outputFile = strings.TrimSuffix(inputFile, suffix)
	} else {
		now := time.Now()
        formattedDate := now.Format("02-01-2006-15-04-05") // DD-MM-YYYY-HH-MM-SS
		if len(inputFile) > 8 {
            outputFile = inputFile[:8] + "-" + formattedDate
		} else {
			outputFile = inputFile + "-" + formattedDate
		}
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
var action string
var allFiles []string
var password string
if len(os.Args) < 3 {
		fmt.Println("Usage is fcryptx option file \n option : \n -e encrypt \n -d decrypt")
		return
	}
option := os.Args[1]
	args := os.Args[2:]
	switch option {
	case "-e" :
		fmt.Println("Option is encrypt")
		action = "encrypt"
	case "-d" :
		fmt.Println("Option is decrypt")
		action = "decrypt"
		default :
		fmt.Printf("option %s does not exist the only valid are -e -d\n" , option)
	}
for _,fs:= range args{
files,err := search(fs)
if err != nil {
	fmt.Println(err)
}
allFiles = append(allFiles,files...)
//allFiles = removeDuplicateAndEmptyStr(allFiles)

} 
fmt.Println("allFiles" , allFiles)
fmt.Println("len all files" ,len(allFiles))
switch action {
case "encrypt" :
	var err error
	password , err = createPassword()
	if err != nil {fmt.Println("Error creating the password")}
	encrypt(allFiles, password)
case "decrypt" :
	var err error
	password,err = readPassword()
	if err != nil {fmt.Println("Error reading the password")}
	decrypt(allFiles , password)
}
}

func encrypt(files []string , password string){
	for _ , file := range files{
	fmt.Printf("Encrypting file %s \n" , file)
	EncryptFile(password , file)
	}
}

func decrypt(files []string , password string){
	for _ , file := range files{
	fmt.Printf("Decrypting file %s \n" , file)
	DecryptFile(password,file)
	}
}

func removeDuplicateAndEmptyStr(strSlice []string) []string {
    allKeys := make(map[string]bool)
    list := []string{}
    for _, item := range strSlice {
        if item == "" {
            continue
        }
        if _, value := allKeys[item]; !value {
            allKeys[item] = true
            list = append(list, item)
        }
    }
    return list
}
func createPassword() (string,error){
valid:= false
var err error
var password string
var err1 error
for valid == false {
	password , err1 = readPassword()
if err1 != nil {
	return "" , err1
}

if test := validatePassword(password); !test {
		fmt.Println("Password must contain 1 digit , 1 uppercase/lowecase letter and 1 special character and must be longer than 8!\n")
		continue
	}
password2,err2 := readPassword()
if err2 != nil {
	return "" , nil
}
if password2 != password {
	fmt.Print("Inserted password are different !\n")
	continue
} 
valid = true

}
err = nil
return string(password) , err
}

func validatePassword(password string) bool {
	// Password must contain at least one uppercase letter, one lowercase letter,
	// one digit, and one special character. It must also be at least 8 characters long.
    if len(password) < 8 {
		return false
	}
	regexUppercase := regexp.MustCompile(`[A-Z]`)
	regexLowercase := regexp.MustCompile(`[a-z]`)
	regexDigit := regexp.MustCompile(`[0-9]`)
	regexSpecialChar := regexp.MustCompile(`[^a-zA-Z0-9]`)
	result := false
	result = regexUppercase.MatchString(password) && regexLowercase.MatchString(password) && regexDigit.MatchString(password) && regexSpecialChar.MatchString(password)
	return result
}

func readPassword() (string,error) {
fmt.Print("Enter password: ")
password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return "" , err
	}
return string(password) , err
	
}