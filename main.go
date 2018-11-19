package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	UserMap map[string]string `yaml:"userMap"`
}

var config = Config{
	UserMap: make(map[string]string),
}

var (
	issuerURL    = flag.String("issuer-url", "https://accounts.google.com", "")
	clientID     = flag.String("client-id", "", "")
	clientSecret = flag.String("client-secret", "", "")
	configFile   = flag.String("config-file", "", "")

	externalURL = flag.String("external-url", "", "")

	cookieName     = flag.String("cookie-name", "_oidc", "")
	cookieDomain   = flag.String("cookie-domain", "", "")
	cookiePath     = flag.String("cookie-path", "/", "")
	cookieHTTPOnly = flag.Bool("cookie-http-only", true, "")
	cookieSecure   = flag.Bool("cookie-secure", true, "")
)

type Cookie struct {
	IDToken      string `json:"i"`
	RefreshToken string `json:"r"`
	State        string `json:"s"`
	Redirect     string `json:"rd"`
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
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthConfig *oauth2.Config
}

func NewServer() *Server {
	provider, err := oidc.NewProvider(context.Background(), *issuerURL)
	if err != nil {
		panic(err)
	}

	return &Server{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: *clientID}),
		oauthConfig: &oauth2.Config{
			ClientID:     *clientID,
			ClientSecret: *clientSecret,
			RedirectURL:  strings.TrimSuffix(*externalURL, "/") + "/callback",
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}
}

func (s *Server) refreshToken(refreshToken string) (string, error) {
	v := url.Values{}
	v.Set("client_id", *clientID)
	v.Set("client_secret", *clientSecret)
	v.Set("refresh_token", refreshToken)
	v.Set("grant_type", "refresh_token")
	resp, err := http.DefaultClient.PostForm(s.provider.Endpoint().TokenURL, v)
	if err != nil {
		return "", err
	}
	var r struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.IDToken, nil
}

func (s *Server) getIdTokenFromRequest(r *http.Request) (string, *Cookie) {
	if user, pass, ok := r.BasicAuth(); ok && user == "_oidc" {
		return pass, nil
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		t := strings.ToLower(parts[0])
		if len(parts) == 2 && (t == "bearer" || t == "token") {
			return parts[1], nil
		}
	}

	cookie := LoadCookie(r)
	return cookie.IDToken, cookie
}

func (s *Server) HandleAuth(rw http.ResponseWriter, r *http.Request) {
	idToken, cookie := s.getIdTokenFromRequest(r)

	// First attempt, verify the token.
	err := s.verifyIDToken(r, rw, idToken)

	// If it worked, return 200 OK.
	if err == nil {
		rw.WriteHeader(http.StatusOK)
		return
	}

	// If verification failed, it may be because it's expired.
	// In this case, try to refresh it.
	if strings.HasPrefix(err.Error(), "oidc: token is expired") && cookie != nil && cookie.RefreshToken != "" {
		if idToken, err = s.refreshToken(cookie.RefreshToken); err == nil {
			// Second attempt, verify the token we got from the refresh.
			err := s.verifyIDToken(r, rw, idToken)

			// If it worked, return 200 OK.
			if err == nil {
				cookie.IDToken = idToken
				SaveCookie(rw, cookie)
				rw.WriteHeader(http.StatusOK)
				return
			}

			// If it didn't work, carry on and handle it like other failures.
		}
	}

	// If the idToken came from a cookie, clear out the cookie. This prevents
	// ongoing verification and refresh attempts of a bad cookie.
	if cookie != nil {
		SaveCookie(rw, &Cookie{})
	}

	// WWW-Authenticate is needed for Git to realize it needs authentication.
	rw.Header().Set("WWW-Authenticate", "Basic")

	rw.WriteHeader(http.StatusUnauthorized)
}

func (s *Server) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	state := generateRandomState()
	SaveCookie(rw, &Cookie{State: state, Redirect: r.URL.Query().Get("rd")})
	http.Redirect(rw, r, s.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent")), http.StatusFound)
}

func getUserForEmail(email string) (string, error) {
	emailBytes := []byte(email)
	for k, v := range config.UserMap {
		r := regexp.MustCompile("^" + k + "$")
		match := r.FindSubmatchIndex(emailBytes)
		if match == nil {
			continue
		}

		res := r.Expand(nil, []byte(v), emailBytes, match)
		return string(res), nil
	}
	return "", fmt.Errorf("Unauthorized Email %s", email)
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

	user, err := getUserForEmail(claims.Email)
	if err != nil {
		return err
	}
	rw.Header().Set("X-Auth-Request-User", user)
	rw.Header().Set("X-Auth-Request-Email", claims.Email)

	return nil
}

func (s *Server) HandleLoginCallback(rw http.ResponseWriter, r *http.Request) {
	c := LoadCookie(r)
	if c.State != r.URL.Query().Get("state") {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(rw, "Could not get id_token", http.StatusBadRequest)
		return
	}

	if err := s.verifyIDToken(r, rw, rawIDToken); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	SaveCookie(rw, &Cookie{
		IDToken:      rawIDToken,
		RefreshToken: oauth2Token.RefreshToken,
	})
	if c.Redirect != "" {
		http.Redirect(rw, r, c.Redirect, http.StatusFound)
	} else {
		rw.WriteHeader(http.StatusOK)
	}
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

	cfgData, err := ioutil.ReadFile(*configFile)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(cfgData, &config); err != nil {
		panic(err)
	}

	s := NewServer()

	http.HandleFunc("/login", s.HandleLogin)
	http.HandleFunc("/callback", s.HandleLoginCallback)
	http.HandleFunc("/auth", s.HandleAuth)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
