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

// exp - generates expiry time based on expiry env variable
func exp() time.Time {
	seconds, err := strconv.Atoi(os.Getenv("JWT_EXPIRY"))
	if err != nil {
		fmt.Println("EXPIRY is either missing or invalid")
		os.Exit(1)
	}
	return time.Now().Add(time.Second * time.Duration(seconds))
}

// secret - jwt secret for hash
var secret = os.Getenv("JWT_SECRET")

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
}

// base64Encode - encodes string to base64 string
func base64Encode(data string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

// base64Decode - decodes base64 encoded string
func base64Decode(data string) string {
	slice, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		fmt.Printf("Error decoding string: %s\n", err)
		return ""
	}
	return string(slice)
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
	decodedPayload := base64Decode(encodedPayload)
	err := unmarshalJSON(decodedPayload, payload)
	if err != nil {
		return false
	}
	return time.Now().Before(payload.Exp)
}

// unmarshalJSON - handles unmarshalling JSON strings to objects
func unmarshalJSON(jsonString string, item interface{}) error {
	err := json.Unmarshal([]byte(jsonString), item)
	if err != nil {
		fmt.Printf("Error unmarshalling payload: %s", err)
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

// BuildJWT - takes a claim and builds a jwt token
func BuildJWT(claim *Claim) (string, error) {
	header := &header{"HS256", "JWT"}
	payload := &payload{claim, exp()}

	marshalledHeader, err := marshalJSON(header)
	if err != nil {
		return "", err
	}
	marshalledPayload, err := marshalJSON(payload)
	if err != nil {
		return "", err
	}

	encodedBody := base64Encode(marshalledHeader) + "." + base64Encode(marshalledPayload)
	signature := buildSignature(encodedBody, secret)
	return encodedBody + "." + signature, nil
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
	return parts[2] == buildSignature(parts[0]+"."+parts[1], secret)
}
