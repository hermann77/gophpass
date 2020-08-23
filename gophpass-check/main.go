package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hermann77/gophpass"
)

func main() {

	var password string
	var hash string

	flag.StringVar(&password, "password", "", "password you want to check against a hash")
	flag.StringVar(&hash, "hash", "", "Hash you want to validate")
	flag.Parse()
	
	fmt.Printf("flagArgsLength: %d \n", len(flag.Args()))

	fmt.Printf("password: %s\n", password)
	fmt.Printf("hash: %s\n", hash)

	if len(flag.Args()) > 1 {
		if password == "" {
			password = strings.Join(flag.Args()[1:], "")
			fmt.Printf("password par: %s", password)
		} else {
			fmt.Printf("password NAMED par: %s", password)
		}
		if hash == "" {
			hash = flag.Args()[1]
			fmt.Printf("hash par: %s", hash)
		} else {
			fmt.Printf("hash NAMED par: %s", hash)
		}
	}

	if gophpass.Check(password, hash) {
		fmt.Printf("2. Password and Hash matched\n")
	} else {
		fmt.Printf("2. Password and Hash are NOT matched\n")
		os.Exit(1)
	}
	 
}
   