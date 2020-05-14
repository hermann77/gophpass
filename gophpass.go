// Implementing Drupal 8 phpass algorithm in go
package main

// import bcrypt
import (
    "fmt"
    "bytes"
    "crypto/rand"
    "crypto/sha512"
    "crypto/md5"
    "encoding/base64"
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
    count   int // allowed range is MinCount to MaxCount
}

// InvalidCountError errors
var InvalidCountError = errors.New("Invalid Count");
var InvalidSaltError = errors.New("Invalid Salt");
var bcEncoding = base64.NewEncoding(ITOA64)
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

    hashCount := 16

    if hashCount < MinHashCount {
        hashCount = DefaultHashCount
    }
    p := new(hashed)
    p.count = hashCount

    newSalt, err := generateSalt(hashCount)
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
func generateSalt(hashCount int) ([]byte, error) {
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


// password crypt
func encrypt(password []byte, setting []byte) ([]byte, error) {
// func encrypt(password string, count uint, salt string) ([]byte, error) {    
    // make sure we only pull the first 12 characters
    setting = setting[0:12]
    if !validateSalt(setting) {
        return nil, InvalidSaltError
    }

    salt := setting[4:12]
    data := append(salt, password...)

    fmt.Printf("encrypt :: salt + password: %s \n", data)

    var i, rounds uint64
    rounds = 1 << countLog2 // countLog2 = 16 by default and set as static var
    
    for i = 0; i < rounds; i++ {
        checksum := sha512.Sum512(data)
        // reinitialize data slice
     //   data = checksum[0:64]
        data = append(checksum[:64], password...) // in Drupal 8 we make hash from pervious hash + password
    }
    
    output := append(setting, base64Encode(data)...)
    return output[:55], nil
}


// Check password hash with stored hash
func Check(password string, hash string) bool {

    storedHash := hash

    if hash[:2] == "U$" {
        fmt.Printf("Drupal 7 md5 hashes")
        storedHash = hash[1:]

        passwordString := md5.New()
        io.WriteString(passwordString, password)
        password = string(passwordString.Sum(nil))
    }

    hashType := storedHash[:3]

    switch hashType {
    case "$S$":
        fmt.Printf("Drupal 7/8 sha512 hashes\n")
        passwordByte := []byte(password)
        storedHashByte := []byte(storedHash)
        computedHash, _ := encrypt(passwordByte, storedHashByte)

        fmt.Printf("storedHash %s \n", storedHash)
        fmt.Printf("computedHash %s \n", computedHash)

        if(storedHash == string(computedHash)) {
            fmt.Printf("Hashes matched\n")
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

// check if a byte is next up on the read buffer 
func byteCheck(r *bytes.Buffer, b byte) bool {
    got, err := r.ReadByte()
    if err != nil {
        return false
    }

    if got != b {
        r.UnreadByte()
        return false
    }

    return true
}


func base64Encode(src []byte) []byte {
    n := bcEncoding.EncodedLen(len(src))
    dst := make([]byte, n)
    bcEncoding.Encode(dst, src)
    for dst[n-1] == '=' {
        n--
    }
    return dst[:n]
}


func main() {
   
   /* 
    hash, _ := HashedPassword("testPasswort", 16)
    fmt.Printf("Hash: %s \n", hash)
    fmt.Printf("Hash-Length %d \n", len(hash))
   */

    Check("testPasswort", "$S$EAyVqxsVM5L3tB2SJrbwYl4v8DfqJN5poY6uScb54cj3wVjEqTLC")
    
}
