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
  DecryptString(`Looooong encoded string`)
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

  //Decrypt a ciphertext that was previously encrypted.
  //Note that we dont actually specify the key name.
  //I guess the ciphertext already encodes it?
  dataKeyOutput, err := kmsClient.Decrypt(&kms.DecryptInput{
    CiphertextBlob: p.Key,
  })
  if err == nil { // dataKeyOutput is now filled
    fmt.Println(dataKeyOutput)
  } else {
    fmt.Println("error: ", err)
  }

  key := &[decryptKeyLength]byte{}
  copy(key[:], dataKeyOutput.Plaintext)

  // Decrypt message
  var plaintext []byte
  plaintext, ok := secretbox.Open(plaintext, p.Message, p.Nonce, key)
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

