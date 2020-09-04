package apple_signin

// TokenResponse is based on https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
type TokenResponse struct {
	// (Reserved for future use) A token used to access allowed data. Currently, no data set has been defined for access.
	AccessToken string `json:"access_token"`

	// The amount of time, in seconds, before the access token expires. You can revalidate with the "RefreshToken"
	ExpiresIn int `json:"expires_in"`

	// A JSON Web Token that contains the user’s identity information.
	IDToken string `json:"id_token"`

	// The refresh token used to regenerate new access tokens. Store this token securely on your server.
	RefreshToken string `json:"refresh_token"`

	// The type of access token. It will always be "bearer".
	TokenType string `json:"token_type"`

	// Parsed Claims form IDToken
	Claims Claims `json:"-"`
}

// ErrorResponse is based on https://developer.apple.com/documentation/sign_in_with_apple/errorresponse
type ErrorResponse struct {
	// A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
	// Possible values: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`
	Error string `json:"error"`
}

func (tknResp *TokenResponse) parseClaims() error {
	claims, err := parseClaims(tknResp.IDToken)
	if err != nil {
		return err
	}
	tknResp.Claims = claims
	return nil
}
