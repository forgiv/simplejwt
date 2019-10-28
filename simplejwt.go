// Package simplejwt provides a simple set of functions for creating and validating HS256 JWT tokens.
package simplejwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// MuteFallbackLogs - config variable for muting logs about using default values
	MuteFallbackLogs = false
	// ExpiryName - name of environment variable used for JWT expiry time
	ExpiryName = "JWT_EXPIRY"
	// SecretName - name of environment variable used for JWT secret key
	SecretName = "JWT_SECRET"
	// RefreshName - name of environment variable used for JWT refresh time
	RefreshName = "JWT_REFRESH"
)

// Claim - data to be placed in payload
type Claim struct {
	Data interface{} `json:"data"`
}

// header - jwt header struct
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"type"`
}

// payload - jwt payload struct
type payload struct {
	*Claim
	Exp time.Time `json:"exp"`
	Iat time.Time `json:"iat"`
}

// exp - generates expiry time based on expiry env variable
// Defaults to 24 hours if environment variable is not set.
func exp() time.Time {
	seconds, err := strconv.Atoi(os.Getenv(ExpiryName))
	if err != nil {
		if !MuteFallbackLogs {
			fmt.Println("Expiry environment variable not set, or invalid. Using default.")
		}
		seconds = 60 * 60 * 24
	}
	return time.Now().Add(time.Second * time.Duration(seconds))
}

// secret - jwt secret for hash
// Exits program if environment variable is not set.
func secret() string {
	secret := os.Getenv(SecretName)
	if secret == "" {
		fmt.Println("JWT_SECRET environment variable is either empty or not set.")
		os.Exit(10)
	}
	return secret
}

// refresh - generates refresh time based on expiry time and refresh environment variable
// Defaults to 48 hours after expiry time if environment variable is not set.
func refresh(exp time.Time) time.Time {
	seconds, err := strconv.Atoi(os.Getenv(RefreshName))
	if err != nil {
		if !MuteFallbackLogs {
			fmt.Println("Expiry environment variable not set, or invalid. Using default.")
		}
		seconds = 60 * 60 * 48
	}
	return exp.Add(time.Second * time.Duration(seconds))
}

// base64Encode - encodes string to base64 string
func base64Encode(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

// base64Decode - decodes base64 encoded string
func base64Decode(data string) (string, error) {
	slice, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		fmt.Printf("Error decoding string: %s\n", err)
		return "", err
	}
	return string(slice), nil
}

// buildSignature - takes encodedbody (header.payload) and secret and hashes signature
func buildSignature(encodedBody, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encodedBody))
	signature := mac.Sum(nil)
	return base64Encode(string(signature))
}

// validateEXP - validates expiry in token payload
func validateEXP(encodedPayload string) bool {
	payload := &payload{}
	decodedPayload, err := base64Decode(encodedPayload)
	if err != nil {
		return false
	}
	err = unmarshalJSON(decodedPayload, payload)
	if err != nil {
		return false
	}
	return time.Now().Before(payload.Exp)
}

// validateRefresh - validates if token is eligible for refresh
func validateRefresh(encodedPayload string) bool {
	payload := &payload{}
	decodedPayload, err := base64Decode(encodedPayload)
	if err != nil {
		return false
	}
	err = unmarshalJSON(decodedPayload, payload)
	if err != nil {
		return false
	}
	return time.Now().Before(refresh(payload.Exp))
}

// unmarshalJSON - handles unmarshalling JSON strings to objects
func unmarshalJSON(jsonString string, item interface{}) error {
	err := json.Unmarshal([]byte(jsonString), item)
	if err != nil {
		fmt.Printf("Error unmarshalling payload: %s\n", err)
		return err
	}
	return nil
}

// marshalJSON - handles marshalling objects to JSON string
func marshalJSON(item interface{}) (string, error) {
	itemString, err := json.Marshal(item)
	if err != nil {
		fmt.Printf("Error marshalling to json: %s\n", err)
		return "", err
	}
	return string(itemString), nil
}

// ValidateJWT - validates a jwt token
func ValidateJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	if !validateEXP(parts[1]) {
		return false
	}
	return parts[2] == buildSignature(parts[0]+"."+parts[1], secret())
}

// BuildJWT - takes a claim and builds a jwt token
func BuildJWT(claim *Claim) (string, error) {
	header := &header{"HS256", "JWT"}
	payload := &payload{claim, exp(), time.Now()}
	marshalledHeader, err := marshalJSON(header)
	if err != nil {
		return "", err
	}
	marshalledPayload, err := marshalJSON(payload)
	if err != nil {
		return "", err
	}
	encodedBody := base64Encode(marshalledHeader) + "." + base64Encode(marshalledPayload)
	signature := buildSignature(encodedBody, secret())
	return encodedBody + "." + signature, nil
}

// RefreshJWT - validates token can be refreshed then refreshes
func RefreshJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if parts[2] == buildSignature(parts[0]+"."+parts[1], secret()) {
		if validateRefresh(parts[1]) {
			payload := &payload{}
			decodedPayload, err := base64Decode(parts[1])
			if err != nil {
				return "", err
			}
			err = unmarshalJSON(decodedPayload, payload)
			if err != nil {
				return "", err
			}
			payload.Exp = exp()
			payload.Iat = time.Now()
			marshalledPayload, err := marshalJSON(payload)
			if err != nil {
				return "", err
			}
			encodedBody := parts[0] + "." + base64Encode(marshalledPayload)
			signature := buildSignature(parts[0]+"."+base64Encode(marshalledPayload), secret())
			return encodedBody + "." + signature, nil
		}
		return "", fmt.Errorf("Outside refresh window")
	}
	return "", fmt.Errorf("Unable to validate JWT signature")
}
