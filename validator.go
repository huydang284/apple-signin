package apple_signin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	// ValidationURL is the endpoint for verifying tokens
	ValidationURL string = "https://appleid.apple.com/auth/token"
	// ContentType is the one expected by Apple
	ContentType string = "application/x-www-form-urlencoded"
	// UserAgent is required by Apple or the request will fail
	UserAgent string = "apple-signin"
	// AcceptHeader is the content that we are willing to accept
	AcceptHeader string = "application/json"
)

// Client implements ValidationClient
type Client struct {
	validationURL                    string
	appleClientID, appleClientSecret string
	httpClient                       *http.Client
}

// New creates a Client object
func New(appleClientID, appleClientSecret string) *Client {
	client := &Client{
		validationURL:     ValidationURL,
		appleClientID:     appleClientID,
		appleClientSecret: appleClientSecret,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

func (c *Client) SetCustomValidationURL(customValidationURL string) {
	c.validationURL = customValidationURL
}

func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

func (c *Client) VerifyWebToken(ctx context.Context, code, redirectURI string) (TokenResponse, error) {
	return c.doRequest(ctx, ValidateTokenRequest{
		Code:        code,
		RedirectURI: redirectURI,
		GrantType:   GrantTypeAuthorizationCode,
	})
}

func (c *Client) VerifyAppToken(ctx context.Context, code string) (TokenResponse, error) {
	return c.doRequest(ctx, ValidateTokenRequest{
		Code:      code,
		GrantType: GrantTypeAuthorizationCode,
	})
}

func (c *Client) VerifyRefreshToken(ctx context.Context, refreshToken string) (TokenResponse, error) {
	return c.doRequest(ctx, ValidateTokenRequest{
		RefreshToken: refreshToken,
		GrantType:    GrantTypeRefreshToken,
	})
}

func (c *Client) doRequest(ctx context.Context, req ValidateTokenRequest) (TokenResponse, error) {
	req.ClientID = c.appleClientID
	req.ClientSecret = c.appleClientSecret

	httpReq, err := http.NewRequest(http.MethodPost, c.validationURL, strings.NewReader(req.getURLEncoded()))
	if err != nil {
		return TokenResponse{}, err
	}

	httpReq.Header.Add("content-type", ContentType)
	httpReq.Header.Add("accept", AcceptHeader)
	httpReq.Header.Add("user-agent", UserAgent) // apple requires a user agent
	httpReq = httpReq.WithContext(ctx)
	httpRes, err := c.httpClient.Do(httpReq)
	if err != nil {
		return TokenResponse{}, err
	}
	defer httpRes.Body.Close()

	bodyDecoder := json.NewDecoder(httpRes.Body)
	if httpRes.StatusCode != http.StatusOK {
		var errRes ErrorResponse
		err := bodyDecoder.Decode(&errRes)
		if err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, errors.New(errRes.Error)
	}
	var successRes TokenResponse
	err = bodyDecoder.Decode(&successRes)
	if err != nil {
		return TokenResponse{}, err
	}

	err = successRes.parseClaims()
	if err != nil {
		return successRes, err
	}

	return successRes, nil
}
