# 2FA

Google Authenticator Two Factor Authentication (2FA)


##USE

```

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


func get2FaValid(email, issuer, token  string) error {

	otp := TFA{Account: email, Issuer: issuer}
	v, erro := otp.Validate(token)
	if erro != nil {
		return erro
	}
	if !v {
		return errors.New("error validate")
	}
	return nil
}


//OR

type Example struct{
    ...
    tfa *TFA
    ...
}

func NewExample(email, issuer string) *Example{
  	otp := TFA{
		Account: email,
		Issuer:  issuer,
	}  

    return &Example{
        tfa : &otp
    }
}

func (e *Example) TfaQR() (string, string, error) {
	qrBase64, err := e.tfa.QrBase64()
	if err != nil {
		log.Printf("\x1b[31;1mWARNING: qrBytes\x1b[0m")
		return qrBase64, "", err
	}

	return qrBase64, e.tfa.Secret, nil
}


func (e *Example) TfaValid(token  string) error {
	v, erro := e.tfa.Validate(token)
	if erro != nil {
		return erro
	}
	if !v {
		return errors.New("error validate")
	}
	return nil
}


```