package main

import (
	"flag"
	"fmt"
	"os"
//	"strings"

	"github.com/hermann77/gophpass"
)

var password = ""
var hash = ""

func main() {
   
	flag.StringVar(&password, "password", "", "password you want to check against a hash")
	flag.StringVar(&hash, "hash", "", "Hash you want to validate")
	flag.Parse()
	if len(flag.Args()) > 1 {
		if password == "" {
			password = flag.Args()[0]
		}
		if hash == "" {
			hash = flag.Args()[1]
		}
	}

	if gophpass.Check(password, hash) {
		fmt.Printf("1. Password and Hash matched\n")
	} else {
		fmt.Printf("1. Password and Hash are NOT matched\n")
		os.Exit(1)
	}
	 
}
   