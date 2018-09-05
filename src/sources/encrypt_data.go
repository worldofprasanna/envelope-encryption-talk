package main

import (
  "github.com/aws/aws-sdk-go/aws/session"
  "github.com/aws/aws-sdk-go/service/kms"
  "github.com/aws/aws-sdk-go/aws"
  "io/ioutil"
  "strings"
  "encoding/base64"
  "fmt"
  "golang.org/x/crypto/nacl/secretbox"
  "bytes"
  "encoding/gob"
  "crypto/rand"
)

func main() {
  // ENCRYPT_STRING_START_OMIT
  EncryptString("Hello Prasanna !!!")
  // ENCRYPT_STRING_END_OMIT
}

func EncryptString(plainText string) string {
  sess := session.Must(session.NewSession())
  kmsClient := kms.New(sess, aws.NewConfig().WithRegion("us-east-1"))
  plainByteArray, _ := ioutil.ReadAll(strings.NewReader(plainText))

  encrypted, err := Encrypt(kmsClient, plainByteArray) // <-- to be implemented
  if err != nil {
    panic(err)
  }
  encodedEncrypted := base64.StdEncoding.EncodeToString(encrypted)
  fmt.Println("Encrypted Text: ", encodedEncrypted)
  return encodedEncrypted
}

func Encrypt(kmsClient *kms.KMS, plaintext []byte) ([]byte, error) {
  // Generate data key

  //provide either the key's arn OR its alias, as shown below:
  //keyId := "arn:aws:kms:us-east-1:779993255822:key/bb1a147c-8600-4558-910d-8b841c8f7493"
  keyId := "alias/test-kms"
  keySpec := "AES_128"
  dataKeyInput := kms.GenerateDataKeyInput{KeyId: &keyId, KeySpec: &keySpec}

  dataKeyOutput, err := kmsClient.GenerateDataKey(&dataKeyInput)
  if err == nil { // dataKeyOutput is now filled
    fmt.Println(dataKeyOutput)
  } else {
    fmt.Println("error: ", err)
  }

  // Initialize payload
  p := &encryptPayload{
    Key:   dataKeyOutput.CiphertextBlob,
    Nonce: &[encryptNonceLength]byte{},
  }

  // Set nonce
  if _, err = rand.Read(p.Nonce[:]); err != nil {
    return nil, err
  }

  // Create key
  key := &[encryptKeyLength]byte{}
  copy(key[:], dataKeyOutput.Plaintext)

  // Encrypt message
  p.Message = secretbox.Seal(p.Message, plaintext, p.Nonce, key)

  buf := &bytes.Buffer{}
  if err := gob.NewEncoder(buf).Encode(p); err != nil {
    return nil, err
  }

  return buf.Bytes(), nil
}

const (
  encryptKeyLength   = 32
  encryptNonceLength = 24
)

type encryptPayload struct {
  Key     []byte
  Nonce   *[encryptNonceLength]byte
  Message []byte
}

