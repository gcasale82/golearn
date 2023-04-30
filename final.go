package main
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"errors"
	"regexp"
	"golang.org/x/crypto/ssh/terminal"
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

func main(){
var action string
var allFiles []string
var password string
//password := "Password123!!!"
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
	fmt.Printf("Encrypting file %s with password %s \n" , file , password)
	}
}

func decrypt(files []string , password string){
	for _ , file := range files{
	fmt.Printf("Decrypting file %s with password %s \n" , file , password)
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