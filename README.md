# Simple JWT [![GoDoc](https://godoc.org/github.com/forgiv/simplejwt?status.svg)](https://godoc.org/github.com/forgiv/simplejwt)

A **VERY** basic JWT implementation for those that just want a basic HS256 JWT token.  
The motiviation for this project was to learn about making JWT tokens in Go, and also because the alternatives are all just a little too complicated when I want a quick and dirty setup.

**This package is still in an unstable state**  
**You probably shouldn't use this package in production.**

## Requirements

This package doesn't depend on anything other than the standard go library.  
However, a couple environment variables are required to get it working.
- `JWT_SECRET` is a random string for generating your hash
- `JWT_EXPIRY` is the number of seconds before a token expires
  - Defaults to 24 hours if environment variable isn't found
- `JWT_REFRESH` is the number of seconds after expiration that a token can no longer be refreshed
  - Defaults to 48 hours after expiry

## Usage

Make a claim
```go
claim := &simplejwt.Claim{}
```

Optionally you can give your claim some data.
```go
claim.Data = "Hello"
```

Claim data is an interface so anything goes.
```go
type User struct {
  Username string `json:"username"`
  password string // only exported data is used when creating JWT
}
user := &User{ "Hiram", "simpleJWT" }

claim := &simplejwt.Claim{}
claim.Data = user
// or more simply claim := &Claim{ user }
```

Once you have your claim, you can build your JWT.
```go
token, err := simplejwt.BuildJWT(claim)
if err != nil {
  // Handle the error!
}
```

When it's time to verify a token, just use `ValidateJWT`
```go
if simplejwt.ValidateJWT(token) {
  fmt.Println("Yay, we have a valid token!")
} else {
  fmt.Println("Boo, this token isn't valid!")
}
```

Want to refresh an expired token?  
`RefreshJWT` will refresh the `expiry` and `issued at` dates of a JWT token.  
It uses the existing data in the token to create a new token, so if you have new data to put in the token don't rely on a refresh.  
`RefreshJWT` will return an error if the token cannot be refreshed for any reason.
```go
newToken, err := simplejwt.RefreshJWT(oldToken)
if err != nil {
  // Handle error
}
```

Want to use different environment variables?  
Set them before you call `BuildJWT`, `ValidateJWT`, `RefreshJWT`.
```go
simplejwt.ExpiryName = "MY_CUSTOM_EXPIRY_VARIABLE"
simplejwt.SecretName = "MY_CUSTOM_SECRET_VARIABLE"
simplejwt.RefreshName = "MY_CUSTOM_REFRESH_VARIABLE"
```

## Misc Knowledge

If the package can't find the expiry or refresh environment variables it falls back to using the defaults while also logging that it's being used. This can get annoying if you plan to use the defaults. In order to suppress these logs, just set the `MuteFallbackLogs` variable to `true`
```go
simplejwt.MuteFallbackLogs = true
```

## Caveats

- Only supports a single Claim  
~~Refreshing isn't handled and must be done manually~~  
~~Required environment variable names are too general and can cause issues~~  

## Roadmap

> All versions before version v1.0.0 are volatile

- v0.2.0
  - [x] mass refactor
  - [x] first test
- v0.3.0
  - [x] better error handling
  - [x] change env var names
- v0.4.0
  - [x] refreshing tokens
- v0.5.0
  - [ ] multiple claims
