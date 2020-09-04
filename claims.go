package apple_signin

import (
	"github.com/tideland/gorest/jwt"
	"time"
)

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
	Iat time.Time

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
	NonceSupported *bool

	// A String value representing the user’s email address. The email address will be either the user’s real email
	// address or the proxy address, depending on their status private email relay service.
	Email string

	// A String or Boolean value that indicates whether the service has verified the email. The value of this claim is
	// always true, because the servers only return verified email addresses. The value can either be a String (”true”)
	// or a Boolean (true).
	EmailVerified *bool

	// A String or Boolean value that indicates whether the email shared by the user is the proxy address. The value
	// can either be a String (”true” or “false”) or a Boolean (true or false).
	IsPrivateEmail *bool

	// An Integer value that indicates whether the user appears to be a real person. Use the value of this claim to
	// mitigate fraud. The possible values are: 0 (or Unsupported). 1 (or Unknown), 2 (or LikelyReal).
	// For more information, see ASUserDetectionStatus. This claim is present only on iOS 14 and later,
	// macOS 11 and later, watchOS 7 and later, tvOS 14 and later; the claim is not present or supported for web-based apps.
	RealUserStatus int

	// some missing fields from Apple document but exist in response
	AtHash   string
	AuthTime time.Time
}

func parseClaims(idToken string) (Claims, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return Claims{}, err
	}
	claims := Claims{}
	claimsFromIDToken := j.Claims()
	claims.Iss, _ = claimsFromIDToken["iss"].(string)
	claims.Sub, _ = claimsFromIDToken["sub"].(string)
	claims.Aud, _ = claimsFromIDToken["aud"].(string)
	claims.Nonce, _ = claimsFromIDToken["nonce"].(string)
	claims.Email, _ = claimsFromIDToken["email"].(string)
	claims.AtHash, _ = claimsFromIDToken["at_hash"].(string)

	realUserStatus, _ := claimsFromIDToken["real_user_status"].(float64)
	claims.RealUserStatus = int(realUserStatus)

	expSec, _ := claimsFromIDToken["exp"].(float64)
	if expSec > 0 {
		claims.Exp = time.Unix(int64(expSec), 0)
	}
	iatSec, _ := claimsFromIDToken["iat"].(float64)
	if expSec > 0 {
		claims.Iat = time.Unix(int64(iatSec), 0)
	}
	authTimeSec, _ := claimsFromIDToken["exp"].(float64)
	if expSec > 0 {
		claims.AuthTime = time.Unix(int64(authTimeSec), 0)
	}

	claims.NonceSupported = convertBoolInResponse(claimsFromIDToken["nonce_supported"])
	claims.EmailVerified = convertBoolInResponse(claimsFromIDToken["email_verified"])
	claims.IsPrivateEmail = convertBoolInResponse(claimsFromIDToken["is_private_email"])

	return claims, nil
}

func convertBoolInResponse(value interface{}) *bool {
	b, ok := value.(bool)
	if ok {
		return &b
	}
	t, f := true, false
	bStr, _ := value.(string)
	if bStr == "true" {
		return &t
	} else if bStr == "false" {
		return &f
	}
	return nil
}
