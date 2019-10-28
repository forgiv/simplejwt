package simplejwt

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	os.Setenv("JWT_SECRET", "afuishfgbuileflai")
	os.Setenv("JWT_EXPIRY", "1")

	user := &User{"hiram", "password"}
	token, err := BuildJWT(&Claim{user})
	if err != nil {
		fmt.Printf("Failed building JWT with error: %s\n", err)
		t.Fail()
	}

	time.Sleep(2 * time.Second)
	if ValidateJWT(token) {
		fmt.Println("Expired JWT Passed")
		t.Fail()
	}
}

func TestReassigningPackageVariablesWorks(t *testing.T) {
	os.Setenv("SECRET", "fiehfuiehwabvli")
	os.Setenv("EXPIRY", "1")

	SecretName = "SECRET"
	ExpiryName = "EXPIRY"

	user := &User{"Hiram", "password"}
	token, err := BuildJWT(&Claim{user})
	if err != nil {
		fmt.Printf("Failed building JWT with error: %s\n", err)
		t.Fail()
	}

	time.Sleep(2 * time.Second)
	if ValidateJWT(token) {
		fmt.Println("Expired JWT Passed")
		t.Fail()
	}
}

func TestValidateRefresh(t *testing.T) {
	os.Setenv("JWT_SECRET", "aisuhfuialshfiusdhf")
	os.Setenv("JWT_EXPIRY", "1")
	os.Setenv("JWT_REFRESH", "5")

	user := &User{"Hiram", "password"}
	token, err := BuildJWT(&Claim{user})
	if err != nil {
		fmt.Printf("Failed building JWT with error: %s\n", err)
		t.Fail()
	}

	time.Sleep(2 * time.Second)
	if ValidateJWT(token) {
		fmt.Println("Expired JWT Passed")
		t.Fail()
	}

	newToken, err := RefreshJWT(token)
	if err != nil {
		fmt.Printf("Token refresh failed with error: %s", err)
		t.Fail()
	}

	if newToken == token {
		fmt.Println("Refreshed token is not different to original token")
		t.Fail()
	}
}

type User struct {
	Username string `json:"username"`
	password string
}
