package tfa

import (
	"log"
	"testing"
)

func get2FaQR(email, issuer string) (string, string, error) {
	otp := TFA{
		Account: email,
		Issuer:  issuer,
	}

	qrBase64, err := otp.QrBase64()
	if err != nil {
		log.Printf("\x1b[31;1mWARNING: qrBytes\x1b[0m")
		return qrBase64, "", err
	}

	return qrBase64, otp.Secret, nil
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestQRCode(t *testing.T) {
	if base64, secret, err := get2FaQR("test@df.tes", "TEST"); err != nil {
		t.Fatal(err)
	} else {
		log.Println(base64, secret)
	}

}
