package main

import (
   "fmt"
   "crypto/sha256"
	//"encoding/hex"
	"io/ioutil"
	"time"
)

func Sha256(data []byte)[]byte{
	digest:=sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}

func main() {
   data, err := ioutil.ReadFile("test.txt")
   if err != nil {
       panic(err)
   }

   str := string(data)

   startTime := time.Now()
   result := Sha256([]byte(str))

   cost := time.Since(startTime)
	fmt.Printf("cost = [%s]\n", cost)

   fmt.Println("result: ", result)
}