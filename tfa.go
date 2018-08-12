package tfa

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/url"
	"strings"

	"github.com/dgryski/dgoogauth"
	qr "github.com/skip2/go-qrcode"
)

type TFA struct {
	Account string
	Issuer  string
	Secret  string
}

func (tfa *TFA) Validate(token string) (bool, error) {

	hasher := sha1.New()
	hasher.Write([]byte(tfa.Account))
	sha := base32.StdEncoding.EncodeToString(hasher.Sum(nil))
	otpConfig := &dgoogauth.OTPConfig{
		Secret:      strings.TrimSpace(string(sha)),
		WindowSize:  3,
		HotpCounter: 0,
	}

	trimmedToken := strings.TrimSpace(token)

	// Validate token
	return otpConfig.Authenticate(trimmedToken)
}

func (tfa *TFA) code() (*qr.QRCode, error) {
	hasher := sha1.New()
	hasher.Write([]byte(tfa.Account))
	tfa.Secret = base32.StdEncoding.EncodeToString(hasher.Sum(nil))
	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		return nil, err
	}

	URL.Path += "/" + url.PathEscape(tfa.Issuer) + ":" + url.PathEscape(tfa.Account)

	params := url.Values{}
	params.Add("secret", tfa.Secret)
	params.Add("issuer", tfa.Issuer)
	params.Add("digits", "6")
	params.Add("period", "30")
	params.Add("algorithm", "SHA1")
	URL.RawQuery = params.Encode()
	urlString := URL.String()
	fmt.Printf("URL is %s\n", urlString)

	return qr.New(urlString, qr.Medium)
}

func (tfa *TFA) QR() ([]byte, error) {

	code, err := tfa.code()
	if err != nil {
		return nil, err
	}

	return code.PNG(300)
}

func (tfa *TFA) QrBase64() (string, error) {

	code, err := tfa.code()
	if err != nil {
		return "", err
	}
	var buff bytes.Buffer
	png.Encode(&buff, code.Image(300))

	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buff.Bytes()), nil
}
