package simpleJWT

import (
	"os"
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	os.Setenv("SECRET", "afuishfgbuileflai")
	os.Setenv("EXPIRY", "1")

	user := &User{"hiram", "password"}
	token := BuildJWT(&Claim{user})

	time.Sleep(2)

	if !ValidateJWT(token) {
		t.Fail()
	}
}

type User struct {
	Username string `json:"username"`
	password string
}
