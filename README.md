# Simple JWT

A VERY basic JWT implementation for those that just want a basic HS256 JWT token.  
The motiviation for this project was too learn about making JWT tokens in Go, and also because the lalternatives are all just a little too complicated when I want a quick and dirty setup.

**You probably shouldn't use this package in production.**

## Usage

Make a claim
```go
claim := &simpleJWT.Claim{}
```

Optionally you can give your claim some data.
```go
claim.Data = "Hello"
```

Claim data is an interface so anything goes.
```go
type User struct {
  Username string `json:"username"`
  password string
}
user := &User{ "Hiram", "simpleJWT" }

claim := &simpleJWT.Claim{}
claim.Data = user
// or more simply claim := &Claim{ user }
```

Once you have your claim, you can build your JWT.
```go
token := simpleJWT.BuildJWT(claim)
```

When it's time to verify a token, just use `ValidateJWT`
```go
if simpleJWT.ValidateJWT(token) {
  fmt.Println("Yay, we have a valid token!")
} else {
  fmt.Println("Boo, this token isn't valid!")
}
```
