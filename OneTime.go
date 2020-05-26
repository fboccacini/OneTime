package main

import (
    "crypto/hmac"
    // "crypto/rand"
    "crypto/md5"
  	"crypto/sha1"
  	"crypto/sha256"
  	"crypto/sha512"
    // "encoding/base64"
    "encoding/base32"
    "strings"
    // "hash"
    "fmt"
    "time"
    // "io"
)


type OneTime struct {
  Secret string
  Step, Length int
  Encryption string
}


func (totp OneTime) Generate(counter int) (passcode string, err error){


  algorithm := sha1.New()
  switch(strings.ToLower(totp.Encryption)){

  case "sha256":
    algorithm = sha256.New()
  case "sha512":
    algorithm = sha512.New()
  case "md5":
    algorithm = md5.New()
  }
  fmt.Println(strings.ToLower(totp.Encryption))
  // As noted in issue #10 and #17 this adds support for TOTP secrets that are
	// missing their padding.
	secret := strings.TrimSpace(totp.Secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	// As noted in issue #24 Google has started producing base32 in lower case,
	// but the StdEncoding (and the RFC), expect a dictionary of only upper case letters.
	secret = strings.ToUpper(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)

	buf := make([]byte, 8)
	mac := hmac.New(algorithm, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)
	if debug {
		fmt.Printf("counter=%v\n", counter)
		fmt.Printf("buf=%v\n", buf)
	}

	mac.Write(buf)
	sum := mac.Sum(nil)

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := totp.Length


	if debug {
		fmt.Printf("offset=%v\n", offset)
		fmt.Printf("value=%v\n", value)
		fmt.Printf("mod'ed=%v\n", mod)
	}

  return int32(value % int64(math.Pow10(l)))

}

func main() {
  debug := True
  secret := "abcdef"
  totp := OneTime{secret, 30, 10, "SHA512"}
  fmt.Println(totp.Generate(time.Now()))
}
