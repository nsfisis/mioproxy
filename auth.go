package main

import (
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func ReadPasswordFromUserInput() (string, error) {
	bs, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	} else {
		return string(bs), nil
	}
}

func GeneratePasswordHash(password string) (string, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	} else {
		return string(bs), nil
	}
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
