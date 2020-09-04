package apple_signin

import (
	"errors"
	"github.com/tideland/gorest/jwt"
	"time"
)

func ParseClaims(idToken string) (Claims, error) {
	j, err := jwt.Decode(idToken)
	if err != nil {
		return Claims{}, err
	}
	claims := Claims{}
	claimsFromIDToken := j.Claims()
	claims.Iss, _ = claimsFromIDToken["iss"].(string)
	claims.Sub, _ = claimsFromIDToken["sub"].(string)
	claims.Aud, _ = claimsFromIDToken["aud"].(string)
	claims.Iat, _ = claimsFromIDToken["iat"].(string)
	claims.Nonce, _ = claimsFromIDToken["nonce"].(string)
	claims.Email, _ = claimsFromIDToken["email"].(string)
	claims.RealUserStatus, _ = claimsFromIDToken["real_user_status"].(int)

	expSec, _ := claimsFromIDToken["exp"].(int64)
	if expSec > 0 {
		claims.Exp = time.Unix(expSec, 0)
	}

	claims.NonceSupported, err = convertBoolInResponse(claimsFromIDToken["nonce_supported"])
	if err != nil {
		return Claims{}, err
	}

	claims.EmailVerified, err = convertBoolInResponse(claimsFromIDToken["email_verified"])
	if err != nil {
		return Claims{}, err
	}

	claims.IsPrivateEmail, err = convertBoolInResponse(claimsFromIDToken["is_private_email"])
	if err != nil {
		return Claims{}, err
	}

	return claims, nil
}

func convertBoolInResponse(value interface{}) (bool, error) {
	b, ok := value.(bool)
	if ok {
		return b, nil
	}
	bStr, _ := value.(string)
	if bStr == "true" {
		return true, nil
	} else if bStr == "false" {
		return false, nil
	}
	return false, errors.New("invalid bool value")
}
