package apple_signin

import (
	"net/url"
	"time"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// ValidateTokenRequest is based on https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
type ValidateTokenRequest struct {
	// The identifier (App ID or Services ID) for your app.
	// The identifier must not include your Team ID, to help mitigate sensitive data exposure to the end user.
	// This parameter is required for both authorization code and refresh token validation requests.
	ClientID string

	// A secret JSON Web Token, generated by the developer,
	// that uses the Sign in with Apple private key associated with your developer account.
	// This parameter is required for both authorization code and refresh token validation requests.
	ClientSecret string

	// The authorization code received in an authorization response sent to your app.
	// The code is single-use only and valid for five minutes.
	// This parameter is required for authorization code validation requests.
	Code string

	// The grant type determines how the client app interacts with the validation server.
	// This parameter is required for both authorization code and refresh token validation requests.
	// For authorization code validation, use `authorization_code`. For refresh token validation requests, use `refresh_token`.
	GrantType string

	// The refresh token received from the validation server during a authorization request.
	// This parameter is required for refresh token validation requests.
	RefreshToken string

	// The destination URI provided in the authorization request when authorizing a user with your app, if applicable.
	// The URI must use the HTTPS protocol, include a domain name, and cannot contain an IP address or localhost.
	// This parameter is required for authorization code validation requests.
	RedirectURI string
}

func (r ValidateTokenRequest) getURLEncoded() string {
	uv := make(url.Values)
	uv.Set("client_id", r.ClientID)
	uv.Set("client_secret", r.ClientSecret)
	uv.Set("code", r.Code)
	uv.Set("grant_type", r.GrantType)
	uv.Set("refresh_token", r.RefreshToken)
	uv.Set("redirect_uri", r.RedirectURI)
	return uv.Encode()
}

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
}

// ErrorResponse is based on https://developer.apple.com/documentation/sign_in_with_apple/errorresponse
type ErrorResponse struct {
	// A string that describes the reason for the unsuccessful request. The string consists of a single allowed value.
	// Possible values: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`
	Error string `json:"error"`
}

type Claims struct {
	// The issuer registered claim identifies the principal that issued the identity token. Since Apple generates
	// the token, the value is https://appleid.apple.com.
	Iss string

	// The subject registered claim identifies the principal that is the subject of the identity token.
	// Since this token is meant for your application, the value is the unique identifier for the user.
	Sub string

	// The audience registered claim identifies the recipient for which the identity token is intended.
	// Since the token is meant for your application, the value is the client_id from your developer account.
	Aud string

	// The issued at registered claim indicates the time at which Apple issued the identity token,
	// in terms of the number of seconds since Epoch, in UTC.
	Iat string

	// The expiration time registered identifies the time on or after which the identity token will expire,
	// in terms of number of seconds since Epoch, in UTC. The value must be greater than the current date/time
	// when verifying the token.
	Exp time.Time

	// A String value used to associate a client session and the identity token. This value is used to mitigate replay
	// attacks and is present only if passed during the authorization request.
	Nonce string

	// A Boolean value that indicates whether the transaction is on a nonce-supported platform.
	// If you sent a nonce in the authorization request but do not see the nonce claim in the identity token,
	// check this claim to determine how to proceed. If this claim returns true, you should treat nonce as
	// mandatory and fail the transaction; otherwise, you can proceed treating the nonce as options.
	NonceSupported bool

	// A String value representing the user’s email address. The email address will be either the user’s real email
	// address or the proxy address, depending on their status private email relay service.
	Email string

	// A String or Boolean value that indicates whether the service has verified the email. The value of this claim is
	// always true, because the servers only return verified email addresses. The value can either be a String (”true”)
	// or a Boolean (true).
	EmailVerified bool

	// A String or Boolean value that indicates whether the email shared by the user is the proxy address. The value
	// can either be a String (”true” or “false”) or a Boolean (true or false).
	IsPrivateEmail bool

	// An Integer value that indicates whether the user appears to be a real person. Use the value of this claim to
	// mitigate fraud. The possible values are: 0 (or Unsupported). 1 (or Unknown), 2 (or LikelyReal).
	// For more information, see ASUserDetectionStatus. This claim is present only on iOS 14 and later,
	// macOS 11 and later, watchOS 7 and later, tvOS 14 and later; the claim is not present or supported for web-based apps.
	RealUserStatus int
}
