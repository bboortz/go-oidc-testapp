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

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	port         = getenv("PORT", "9000")
	clientID     = getenv("OAUTH2_CLIENT_ID", "MYCLIENTID")
	clientSecret = getenv("OAUTH2_CLIENT_SECRET", "MYCLIENTSECRET")
	redirectURL  = getenv("REDIRECT_URL", "http://localhost:9000/auth/callback")
	appNonce     = getenv("OAUTH2_NONCE", "a sUp3r s3cR3t n0nCe")
	state        = randomString(128) // Don't do this in production.
	ctx          context.Context
	config       oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
)

func getenv(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}

	return value
}

func printEnvVars() {
	for _, pair := range os.Environ() {
		fmt.Println(pair)
	}
}

func seed() {
	rand.Seed(genSeed())
	rand.Seed(int64(randomInt64(0, math.MaxInt64)))
}

func genSeed() int64 {
	return time.Now().UTC().UnixNano() + int64(randomInt(0, 9999999))
}

func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randomInt(65, 90))
	}
	return string(bytes)
}

func randomInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

func randomInt64(min int64, max int64) int64 {
	return min + rand.Int63n(max-min)
}

func claimNonce(nonce string) error {
	if nonce != appNonce {
		return errors.New("unregonized nonce")
	}
	return nil
}

func indexRoute(w http.ResponseWriter, r *http.Request) {
	const htmlStr = `<html><body>
				    <a href="/auth/login">Log in with Google</a>
			        </body></html>`
	fmt.Fprintf(w, htmlStr)
}

func loginRoute(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(appNonce)), http.StatusFound)
}

func callbackRoute(w http.ResponseWriter, r *http.Request) {
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

	resp := struct {
		OAuth2Token    *oauth2.Token
		RawAccessToken string
		RawIDToken     string
		IDToken        *oidc.IDToken
		IDTokenClaims  *json.RawMessage // ID Token payload is just JSON.

		UserInfo *oidc.UserInfo
	}{oauth2Token, oauth2Token.AccessToken, rawIDToken, idToken, new(json.RawMessage), userInfo}
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
}

func main() {
	printEnvVars()

	ctx = context.Background()
	var err error

	provider, err = oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID:       clientID,
		SkipNonceCheck: false,
		ClaimNonce:     claimNonce,
	}
	verifier = provider.Verifier(oidcConfig)

	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", indexRoute)
	http.HandleFunc("/auth/login", loginRoute)
	http.HandleFunc("/auth/callback", callbackRoute)

	log.Printf("listening on http://%s/", port)
	log.Printf("redirect url: %s", redirectURL)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
