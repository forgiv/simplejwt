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
		fmt.Println("Failed building JWT")
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
		fmt.Println("Failed building JWT")
		t.Fail()
	}

	time.Sleep(2 * time.Second)
	if ValidateJWT(token) {
		fmt.Println("Expired JWT Passed")
		t.Fail()
	}
}

type User struct {
	Username string `json:"username"`
	password string
}
