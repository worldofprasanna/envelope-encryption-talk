package main

import (
  "github.com/aws/aws-sdk-go/service/kms"
  "encoding/base64"
  "encoding/gob"
  "bytes"
  "fmt"
  "golang.org/x/crypto/nacl/secretbox"
  "github.com/aws/aws-sdk-go/aws/session"
  "github.com/aws/aws-sdk-go/aws"
)

func main() {
  // DECRYPT_STRING_START_OMIT
  DecryptString(`Looooong encrypted string`)
  // DECRYPT_STRING_END_OMIT
}

func DecryptString(cipherText string) string {
  sess := session.Must(session.NewSession())
  kmsClient := kms.New(sess, aws.NewConfig().WithRegion("us-east-1"))
  decrypted, err := Decrypt(kmsClient, cipherText) // <-- to be implemented
  if err != nil {
    panic(err)
  }
  fmt.Println("Decrypted Text: ", string(decrypted))
  return ""
}

func Decrypt(kmsClient *kms.KMS, ciphertext string) ([]byte, error) {
  cipherText, _ := base64.StdEncoding.DecodeString(ciphertext)
  // Decode ciphertext with gob
  var p decryptPayload
  gob.NewDecoder(bytes.NewReader(cipherText)).Decode(&p)

  //GET_DECRYPT_DATAKEY_START_OMIT
  dataKeyOutput, err := kmsClient.Decrypt(&kms.DecryptInput{
    CiphertextBlob: p.Key,
  })
  //GET_DECRYPT_DATAKEY_END_OMIT
  if err == nil { // dataKeyOutput is now filled
    fmt.Println(dataKeyOutput)
  } else {
    fmt.Println("error: ", err)
  }

  //DECRYPT_START_OMIT
  key := &[decryptKeyLength]byte{}
  copy(key[:], dataKeyOutput.Plaintext)
  var plaintext []byte
  plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key)
  //DECRYPT_END_OMIT
  if !ok {
    return nil, fmt.Errorf("Failed to open secretbox")
  }
  return plaintext, nil
}

const (
  decryptKeyLength   = 32
  decryptNonceLength = 24
)

type decryptPayload struct {
  Key     []byte
  Nonce   *[decryptNonceLength]byte
  Message []byte
}

