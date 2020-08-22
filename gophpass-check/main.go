package main


import (
	"github.com/hermann77/gophpass"
)





func main() {
   
	/*   
	   hash, _ := HashedPassword("testPassword", 16)
	   fmt.Printf("Hash: %s \n", hash)
	   fmt.Printf("Hash-Length %d \n", len(hash))
   */
   
	   gophpass.Check("testPassword", "$S$Em2lMf9zE4rj0yyTNb3X5n7eyl/ST8aZ0lADIwlPOR5f.m9HhUxw")

	
   
   }
   