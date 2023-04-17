package main

import (
	"fmt"
	"os"
	"regexp"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}
	if test := validatePassword(string(password)); !test {
		fmt.Println("Password must contain 1 digit , 1 uppercase/lowecase letter and 1 special character")
	}
	fmt.Println("\nPassword entered:", string(password))
}

func validatePassword(password string) bool {
	// Password must contain at least one uppercase letter, one lowercase letter,
	// one digit, and one special character. It must also be at least 8 characters long.
	result := false
	result = containsUppercase(password) && containsUppercase(password) && containsSpecialChar(password) && isStringLong(password)
	return result
}
func containsUppercase(str string) bool {
	regex := regexp.MustCompile(`[A-Z]`)
	return regex.MatchString(str)
}

func containsLowercase(str string) bool {
	regex := regexp.MustCompile(`[a-z]`)
	return regex.MatchString(str)
}

func containsDigit(str string) bool {
	regex := regexp.MustCompile(`[0-9]`)
	return regex.MatchString(str)
}

func containsSpecialChar(str string) bool {
	regex := regexp.MustCompile(`[^a-zA-Z0-9]`)
	return regex.MatchString(str)
}
func isStringLong(str string) bool {
    return len(str) > 8
}
