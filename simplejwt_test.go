package simplejwt

import (
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
		t.Fail()
	}

	time.Sleep(2)

	if !ValidateJWT(token) {
		t.Fail()
	}
}

type User struct {
	Username string `json:"username"`
	password string
}
