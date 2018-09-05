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
  "crypto/rand"
  "bytes"
  "encoding/gob"
)

func main() {
  // ENCRYPT_STRING_START_OMIT
  EncryptString("Hello Prasanna !!!")
  // ENCRYPT_STRING_END_OMIT
}

func EncryptString(plainText string) string {
  // KMS_INIT_START_OMIT
  sess := session.Must(session.NewSession())
  kmsClient := kms.New(sess, aws.NewConfig().WithRegion("us-east-1"))
  // KMS_INIT_END_OMIT
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
  // CREATE_DATA_KEY_START_OMIT
  keyId := "alias/test-kms"
  keySpec := "AES_128"
  dataKeyInput := kms.GenerateDataKeyInput{KeyId: &keyId, KeySpec: &keySpec}

  dataKeyOutput, err := kmsClient.GenerateDataKey(&dataKeyInput)
  // CREATE_DATA_KEY_END_OMIT
  if err == nil {
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

  // ENCRYPT_START_OMIT
  key := &[encryptKeyLength]byte{}
  copy(key[:], dataKeyOutput.Plaintext)
  p.Message = secretbox.Seal(p.Message, plaintext, p.Nonce, key)
  // ENCRYPT_END_OMIT

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

