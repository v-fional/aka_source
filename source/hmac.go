package main

import (
   "crypto/hmac"
   "crypto/sha256"
   "fmt"
   //"io"
   "time"
   "io/ioutil"
)

func generateHMAC(rawData []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	//io.Write(h, rawData)
	h.Write(rawData)
	return h.Sum(nil)
 }


func main() {

	data, err := ioutil.ReadFile("test.txt")
   if err != nil {
       panic(err)
   }

   str := string(data)


   //data := "Hello go"
   key := "123456"

   startTime := time.Now()

   str1 := generateHMAC([]byte(str), []byte(key))
   cost := time.Since(startTime)
	fmt.Printf("hmac cost = [%s]\n", cost)

    fmt.Println(str1)

}