// Package gophpass is implementing Drupal 8 phpass algorithm in go
// This package rovides the ability to create and validate by phpass hashed
// passwords.  
// For more details: http://www.openwall.com/phpass/ 
// This code is a port of the Drupal 8 implimentation of phpass:
// https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21Password%21PhpassHashedPassword.php/8.2.x
//
// The code is not 100% complete. 

package gophpass

// import bcrypt
import (
    "fmt"
    "bytes"
    "crypto/rand"
    "crypto/sha512"
    "crypto/md5"
    "errors"
    "io"
)

// constants
const (
    MinHashCount        =  7
    MaxHashCount        = 30
    DefaultHashCount    = 15
    HashLength          = 55
    SaltLength          = 6
    ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// hashed struct
type hashed struct {
    hash    []byte
    salt    []byte
    count   uint // allowed range is MinCount to MaxCount
}

// InvalidCountError errors
var InvalidCountError = errors.New("Invalid Count");
var InvalidSaltError = errors.New("Invalid Salt");

var countLog2 uint = 16


// HashedPassword is wrapper for hashPassword
func HashedPassword(password string, cLog2 uint) (string, error) {

    countLog2 = enforceLog2Boundaries(cLog2)

    p, err := hashPassword([]byte(password))
    if err != nil {
        return "", err
    }
    return string(p.hash), nil
}


func enforceLog2Boundaries(cLog2 uint) (uint) {

    if cLog2 < MinHashCount {
        return MinHashCount
    }
    if cLog2 > MaxHashCount {
        return MaxHashCount
    }
    return cLog2
}


// internal function to hash password
func hashPassword(password []byte) (*hashed, error) {

    if countLog2 < MinHashCount {
        countLog2 = DefaultHashCount
    }
    p := new(hashed)
    p.count = countLog2

    newSalt, err := generateSalt(countLog2)
    if err != nil {
        return nil, err
    }
    p.salt = newSalt

    hash, err := encrypt(password, p.salt)
    if err != nil {
        return nil, err
    }
    p.hash = hash
    return p, err 
}


// generate salt
func generateSalt(hashCount uint) ([]byte, error) {
    // new buffer
    rs := bytes.NewBuffer(make([]byte, 0, 61))
    // append $S$
    rs.WriteString("$S$")
    // parse const
    constBytes := []byte(ITOA64)
    rs.WriteByte(constBytes[hashCount])

    unencodedSalt := make([]byte, SaltLength)
    _, err := io.ReadFull(rand.Reader, unencodedSalt)
    if err != nil {
        return nil, err
    }
    encodedSalt := base64Encode(unencodedSalt)

    fmt.Printf("generateSalt :: encodedSalt: %s\n", encodedSalt)

    _, err = rs.Write(encodedSalt)
    if err != nil {
        return nil, err
    }

    fmt.Printf("generateSalt RETURN: %s\n", rs)

    return rs.Bytes(), nil
}


func validateSalt(salt []byte) bool {

    firstChar := string(salt[0:1])
    thirdChar := string(salt[2:3])

    if firstChar != "$" || thirdChar != "$" {
        return false
    }
    return true
}


func getCountLog2(setting []byte) (uint) {

    roundsChar := setting[3:4] // a carachter saved in hash after $S$... The position of this char in alphabet is log2 of rounds number
    ITOA64asByte := []byte(ITOA64)
    roundsLog2 := uint(bytes.Index(ITOA64asByte, roundsChar))

    return roundsLog2 // if 'E' is placed after $S$
}

// password crypt
func encrypt(password []byte, setting []byte) ([]byte, error) {
 // setting is output of generateSalt() or it's stored hash   
 // we pull only the first 12 characters
 setting = setting[0:12]
 if !validateSalt(setting) {
     return nil, InvalidSaltError
 }

 countLog2 := getCountLog2(setting) // @TODO: implement return depending on innput argument
 salt := setting[4:12]
 data := append(salt, password...)
 checksum := sha512.Sum512(data)

 var i, count uint64
 count = 1 << countLog2
 
 i = 0
 for count > 0 {
     data = append(checksum[:], password...)
     checksum = sha512.Sum512(data)
      count--
     i++
 }

 output := append(setting, base64Encode(checksum[0:64])...)
 return output[:55], nil
}


// Check password hash with stored hash
func Check(password string, hash string) bool {

    storedHash := hash

    if hash[:2] == "U$" {
        // Drupal 7 md5 hash
        storedHash = hash[1:]

        passwordString := md5.New()
        io.WriteString(passwordString, password)
        password = string(passwordString.Sum(nil))
    }

    hashType := storedHash[:3]

    switch hashType {
    case "$S$":
        // Drupal 7/8 sha512 hashes
        passwordByte := []byte(password)
        storedHashByte := []byte(storedHash)
        computedHash, _ := encrypt(passwordByte, storedHashByte)

        fmt.Printf("*** storedHash %s \n", storedHash)
        fmt.Printf("*** computedHash %s \n", computedHash)

        if(storedHash == string(computedHash)) {
            return true
        }
        return false
    case "$H$":
    case "$P$":
        fmt.Printf("md5 hashes\n")
        break
    default:
        return false
    }

    return false
}

