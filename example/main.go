package example

import (
	"context"
	"errors"
	"fmt"
	"github.com/huydang284/apple-signin"
	"io/ioutil"
	"os"
)

const (
	AppleSignInClientID = "com.example.app"
	AppleSignInTeamID   = "11AAAAA1AA"
)

func main() {
	appleSignInSecretPath := os.Getenv("APPLE_SIGN_IN_SECRET_PATH")
	appleSignInKeyID := os.Getenv("APPLE_SIGN_IN_KEY_ID")
	if appleSignInSecretPath == "" || appleSignInKeyID == "" {
		panic(errors.New("apple sign in configurations is missing"))
	}
	secret, err := ioutil.ReadFile(appleSignInSecretPath)
	if err != nil {
		panic(err)
	}

	clientSecret, err := apple_signin.GenerateClientSecret(secret, AppleSignInTeamID, AppleSignInClientID, appleSignInKeyID)
	if err != nil {
		panic(err)
	}

	code := "" // this code is sent from mobile app (or web) after user allowed to use Apple Signin
	appleSignInClient := apple_signin.New(AppleSignInClientID, clientSecret)
	tokenResponse, err := appleSignInClient.VerifyAppToken(context.TODO(), code)
	if err != nil {
		panic(err)
	}
	fmt.Println(tokenResponse.Claims.Email)
}
