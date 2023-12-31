package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"time"
)

type MyCustomClaims struct {
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

func main() {
	clientID := "bc51bba0-5b8f-4226-99f4-211b76ac0c45"

	mySigningKey := []byte("my_secret_code")

	token := Generate(clientID, mySigningKey)

	Parse(token, mySigningKey)
}

func Parse(tokenString string, mySigningKey []byte) {
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})
	if err != nil {
		log.Fatal(err)
	} else if claims, ok := token.Claims.(*MyCustomClaims); ok {
		fmt.Println(claims.ClientID, claims.RegisteredClaims.Issuer)
	} else {
		log.Fatal("unknown claims type, cannot proceed")
	}
}

func Generate(clientID string, mySigningKey []byte) string {
	// Create claims with multiple fields populated
	claims := MyCustomClaims{
		clientID,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "test",
			Subject:   "somebody",
			ID:        "1",
			Audience:  []string{"somebody_else"},
		},
	}
	fmt.Printf("client_id: %v\n", claims.ClientID)

	expirationTime := time.Now().Add(10 * time.Minute)

	// Create claims while leaving out some of the optional fields
	claims = MyCustomClaims{
		clientID,
		jwt.RegisteredClaims{
			// Also fixed dates can be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			//	Issuer:    clientID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	ss, err := token.SignedString(mySigningKey)

	fmt.Println(ss, err)

	return ss
}
