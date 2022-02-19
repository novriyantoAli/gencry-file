package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/novriyantoAli/go-gencry-file/function"
)

func main() {

	jsonFile, err := os.Open("config.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		panic(err.Error())
	}

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic(err.Error())
	}

	information := fmt.Sprintf("%s", byteValue)
	// encryption infromation
	function.Encryption(information)

	fmt.Printf("decrypt message: %s", function.Decryption())

	// bytes := make([]byte, 32) //generate a random 32 byte key for AES-256
	// if _, err := rand.Read(bytes); err != nil {
	// 	panic(err.Error())
	// }

	// // key := hex.EncodeToString(bytes) //encode key in bytes to string and keep as secret, put in a vault
	// // fmt.Printf("key to encrypt/decrypt : %s\n", key)

	// information := fmt.Sprintf("%s", byteValue)

	// encrypted := encrypt(information, key)
	// fmt.Printf("encrypted : %s\n", encrypted)

	// f, err := os.Create("config.rein")

	// if err != nil {
	// 	panic(err.Error())
	// }

	// defer f.Close()

	// _, err2 := f.WriteString(encrypted)

	// if err2 != nil {
	// 	panic(err2.Error())
	// }

	// reinFile, err := os.Open("config.rein")
	// // if we os.Open returns an error then handle it
	// if err != nil {
	// 	panic(err.Error())
	// }

	// // defer the closing of our jsonFile so that we can parse it later on
	// defer reinFile.Close()

	// bytesValueRein, err := ioutil.ReadAll(reinFile)
	// if err != nil {
	// 	panic(err.Error())
	// }

	// encryptedRein := fmt.Sprintf("%s", bytesValueRein)

	// decrypted := decrypt(encryptedRein, key)
	// fmt.Printf("decrypted : %s\n", decrypted)

}

func encrypt(config string, k string) string {
	key, err := hex.DecodeString(k)
	if err != nil {
		panic(err.Error())
	}
	plainText := []byte(config)

	// create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plainText, nil)

	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, k string) string {
	key, err := hex.DecodeString(k)
	if err != nil {
		panic(err.Error())
	}

	enc, err := hex.DecodeString(encryptedString)
	if err != nil {
		panic(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := aesGCM.NonceSize()

	nonce, ciphetext := enc[:nonceSize], enc[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, ciphetext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plainText)
}
