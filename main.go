package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	issuerURL    = flag.String("issuer-url", "https://accounts.google.com", "")
	clientID     = flag.String("client-id", "", "")
	clientSecret = flag.String("client-secret", "", "")
	emailDomain  = flag.String("email-domain", "", "")

	cookieName     = flag.String("cookie-name", "_oidc", "")
	cookieDomain   = flag.String("cookie-domain", "", "")
	cookiePath     = flag.String("cookie-path", "", "")
	cookieHTTPOnly = flag.Bool("cookie-http-only", true, "")
	cookieSecure   = flag.Bool("cookie-secure", true, "")
)

type Cookie struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	State        string `json:"state"`
}

func LoadCookie(r *http.Request) *Cookie {
	c, err := r.Cookie(*cookieName)
	if err != nil {
		return &Cookie{}
	}
	data, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return &Cookie{}
	}
	var res Cookie
	if err := json.Unmarshal(data, &res); err != nil {
		return &Cookie{}
	}

	return &res
}

func SaveCookie(rw http.ResponseWriter, c *Cookie) {
	data, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}

	cookie := http.Cookie{
		Name:     *cookieName,
		Domain:   *cookieDomain,
		Path:     *cookiePath,
		HttpOnly: *cookieHTTPOnly,
		Secure:   *cookieSecure,
		Value:    base64.URLEncoding.EncodeToString(data),
	}
	http.SetCookie(rw, &cookie)
}

type Server struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

func NewServer() *Server {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		panic(err)
	}

	return &Server{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: *clientID}),
		oauth2Config: oauth2.Config{
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
			RedirectURL:  "http://localhost:8080/callback",
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}
}

func (s *Server) HandleAuth(rw http.ResponseWriter, r *http.Request) {
	c := LoadCookie(r)
	idToken := c.IDToken
	if user, pass, ok := r.BasicAuth(); ok && user == "_oidc" {
		idToken = pass
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		idToken = strings.TrimPrefix(auth, "Bearer ")
	}

	if err := s.verifyIDToken(r, rw, idToken); err != nil {
		rw.Header().Set("WWW-Authenticate", "Basic")
		rw.WriteHeader(http.StatusUnauthorized)
	} else {
		rw.WriteHeader(http.StatusOK)
	}
}

func (s *Server) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	state := generateRandomState()
	SaveCookie(rw, &Cookie{State: state})
	http.Redirect(rw, r, s.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
}

func (s *Server) verifyIDToken(r *http.Request, rw http.ResponseWriter, rawIDToken string) error {
	// Parse and verify ID Token payload.
	idToken, err := s.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return err
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	if !claims.Verified {
		return fmt.Errorf("Email %s in claim not verified", claims.Email)
	}
	suffix := "@" + *emailDomain
	if !strings.HasSuffix(claims.Email, suffix) {
		return fmt.Errorf("Email %s incorrect domain", claims.Email)
	}
	rw.Header().Set("X-Auth-Request-User", strings.TrimSuffix(claims.Email, suffix))
	rw.Header().Set("X-Auth-Request-Email", claims.Email)

	return nil
}

func (s *Server) HandleLoginCallback(rw http.ResponseWriter, r *http.Request) {
	c := LoadCookie(r)
	if c.State != r.URL.Query().Get("state") {
		panic("State mismatch")
	}

	oauth2Token, err := s.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		panic(err)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		panic("wtf")
	}

	if err := s.verifyIDToken(r, rw, rawIDToken); err != nil {
		panic(err)
	}

	SaveCookie(rw, &Cookie{
		IDToken:      rawIDToken,
		RefreshToken: oauth2Token.RefreshToken,
	})
	rw.WriteHeader(http.StatusOK)
}

func generateRandomState() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes[:])
}

func main() {
	flag.Parse()
	s := NewServer()

	http.HandleFunc("/login", s.HandleLogin)
	http.HandleFunc("/callback", s.HandleLoginCallback)
	http.HandleFunc("/auth", s.HandleAuth)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
