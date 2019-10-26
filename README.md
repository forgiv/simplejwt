# Simple JWT

A **VERY** basic JWT implementation for those that just want a basic HS256 JWT token.  
The motiviation for this project was to learn about making JWT tokens in Go, and also because the alternatives are all just a little too complicated when I want a quick and dirty setup.

**You probably shouldn't use this package in production.**

## Requirements

This package doesn't depend on anything other than the standard go library.  
However, a couple environment variables are required to get it worked.
- `SECRET` is a random string for generating your hash
- `EXPIRY` is the number of seconds before a token expires

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

## Caveats

- Only supports a single Claim
- Refreshing isn't handled and must be done manually  
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
  - [ ] refreshing tokens
- v0.5.0
  - [ ] multiple claims

