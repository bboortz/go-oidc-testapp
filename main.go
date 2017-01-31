/*
This is an example application to demonstrate querying the user info endpoint.
*/
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"time"

	oidc "github.com/coreos/go-oidc"

	"errors"
	//	"github.com/davecgh/go-spew/spew"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	ipport       string = getenv("IPPORT", ":9000")
	clientID     string = getenv("OAUTH2_CLIENT_ID", "MYCLIENTID")
	clientSecret string = getenv("OAUTH2_CLIENT_SECRET", "MYCLIENTSECRET")
	redirectUrl  string = "http://localhost:9000/auth/google/callback"
	appNonce     string = getenv("OAUTH2_NONCE", "asuper secret nonce")
)

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func init() {
	Seed()
}

func Seed() {
	rand.Seed(GenSeed())
	rand.Seed(int64(RandomInt64(0, math.MaxInt64)))
}

func GenSeed() int64 {
	return time.Now().UTC().UnixNano() + int64(RandomInt(0, 9999999))
}

func RandomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(RandomInt(65, 90))
	}
	return string(bytes)
}

func RandomInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

func RandomInt64(min int64, max int64) int64 {
	return min + rand.Int63n(max-min)
}

func ClaimNonce(nonce string) error {
	if nonce != appNonce {
		return errors.New("unregonized nonce")
	}
	return nil
}

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID:       clientID,
		SkipNonceCheck: false,
		ClaimNonce:     ClaimNonce,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := RandomString(128) // Don't do this in production.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		const htmlIndex = `<html><body>
				        <a href="/auth/google/login">Log in with Google</a>
						        </body></html>
								        `
		fmt.Fprintf(w, htmlIndex)
	})

	http.HandleFunc("/auth/google/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(appNonce)), http.StatusFound)
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		//var verifier = provider.Verifier()
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		///
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		//oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			RawIDToken    string
			IDToken       *oidc.IDToken
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
			UserInfo      *oidc.UserInfo
		}{oauth2Token, rawIDToken, idToken, new(json.RawMessage), userInfo}
		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", ipport)
	log.Printf("redirect url: %s", redirectUrl)
	log.Fatal(http.ListenAndServe(ipport, nil))
}
