// Copyright (c) 2013 Nova Roma. All rights reserved. 
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main provides the primary web server for the digital campus 
// application. 
//
// Current implementation (temporarily) is based off of code located at: 
//	github.com/googleplus/gplus-quickstart-go/ 
// Which is licensed under an Apache 2.0 license.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"code.google.com/p/goauth2/oauth"
	"code.google.com/p/google-api-go-client/plus/v1"
	"github.com/gorilla/sessions"
)

const (
	clientID        = "68020998881.apps.googleusercontent.com"
	clientSecret    = "oBCzdUY4p1jGkLWE7fCYoosn"
	applicationName = "Digital Campus"
)

// config is the configuration specification supplied to the OAuth package.
var config = &oauth.Config{
	ClientId:     clientID,
	ClientSecret: clientSecret,
	// Scope determines which API calls you are authorized to make
	Scope:    "https://www.googleapis.com/auth/plus.login",
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://accounts.google.com/o/oauth2/token",
	// Use "postmessage" for the code-flow for server side apps
	RedirectURL: "postmessage",
}

// store initializes the Goriall session store
var store = sessions.NewCookieStore([]byte(randomString(32)))

// indexTemplate is the HTML template we use to present the index page.
var indexTemplate = template.Must(template.ParseFiles("./client/index.html.tmpl"))

// appHandler is a http.Handler which has automatic error handling.
type appHandler func(http.ResponseWriter, *http.Request) *appError

type appError struct {
	Err     error
	Message string
	Code    int
}

// ServeHTTP satifies the http.Handler interface. It runs the appHandler 
// function, and handles any errors that may have occured.
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {
		log.Println(e.Err)
		http.Error(w, e.Message, e.Code)
	}
}

// Token represents an OAuth token response
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IdToken     string `json:"id_token"`
}

// ClaimSet represents an IdToken resposne.
type ClaimSet struct {
	Sub string
}

// randomString returns a random string with the specified length.
func randomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
	// add back missing padding 
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// exchange takes an authentication code and exchanges it with the OAuth 
// endpoint for a Google API bearer token and a Google+ ID
func exchange(code string) (accessToken string, idToken string, err error) {
	// Exchange the authorization code for a credentials object via a POST 
	// request. 
	addr := "https://accounts.google.com/o/oauth2/token"
	values := url.Values{
		"Content-Type":  {"application/x-www-form-urlencoded"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {config.RedirectURL},
		"grant_type":    {"authorization_code"},
	}
	resp, err := http.PostForm(addr, values)
	if err != nil {
		return "", "", fmt.Errorf("Exchanging code: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response body into a token object
	var token Token
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return "", "", fmt.Errorf("Decoding access token: %v", err)
	}

	return token.AccessToken, token.IdToken, nil
}

// decodeIdToken takes an ID Token and decodes it to fetch the Google+ ID within
func decodeIdToken(idToken string) (gplusId string, err error) {
	// An ID token is a cryptographically-signed JSON object encoded in base 64.
	// Normally, it is critical that you validate an ID token before you use it,
	// but since you are communicating directly with Google over an 
	// intermediary-free HTTPS channel and using your Client Secret to 
	// authenticate yourself to Google, you can be confident that the token you
	// recieve really comes from Google and is valid. If your server passes the 
	// ID token to other components of your app, it is extremely important that 
	// the other components validate the token before using it.
	var set ClaimSet
	if idToken != "" {
		// Check that the padding is correct for a base64decode
		parts := strings.Split(idToken, ".")
		if len(parts) < 2 {
			return "", fmt.Errorf("Malformed ID token")
		}
		// Decode the ID token 
		b, err := base64Decode(parts[1])
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
		err = json.Unmarshal(b, &set)
		if err != nil {
			return "", fmt.Errorf("Malformed ID token: %v", err)
		}
	}
	return set.Sub, nil
}

func main() {
	// Static File Serving 
	http.Handle("/content/",
		http.StripPrefix("/content/", http.FileServer(http.Dir("./client"))))

	// Service Handlers 
	http.Handle("/connect", appHandler(connect))
	http.Handle("/disconnect", appHandler(disconnect))
	http.Handle("/people", appHandler(people))

	// UI handlers 
	http.Handle("/", appHandler(index))

	// Start up the server 
	log.Printf("listening on port %s...%s", os.Getenv("PORT"), lineEnding)
	err := http.ListenAndServe(":"+os.Getenv("PORT"), nil)
	if err != nil {
		panic(err)
	}
}

// connect exchanges the one-time authorization code for a token and stores the
// token in the session
func connect(w http.ResponseWriter, r *http.Request) *appError {
	// Ensure that the request is not a forgery and that the user sending this
	// connect request is the expected user
	session, err := store.Get(r, "sessionName")
	if err != nil {
		log.Println("error fetching the session:", err)
		return &appError{err, "Error fetching the session", http.StatusInternalServerError}
	}
	if r.FormValue("state") != session.Values["state"].(string) {
		m := "Invalid state parameter"
		return &appError{errors.New(m), m, http.StatusUnauthorized}
	}

	// Normally, the state is a one-time token; however, this example, we want 
	// the user to be able to connect and disconnect without reloading the page.
	// Thus, for demonstration, we don't implement this best practice. 
	// session.Values["state"] = nil

	// Setup for fetching the code from the request payload 
	x, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return &appError{err, "Error reading code in request body", http.StatusInternalServerError}
	}
	code := string(x)

	accessToken, idToken, err := exchange(code)
	if err != nil {
		return &appError{err, "Error exchanging code for access token", http.StatusInternalServerError}
	}
	gplusID, err := decodeIdToken(idToken)
	if err != nil {
		return &appError{err, "Error decoding ID token", http.StatusInternalServerError}
	}

	// Check if the user is already connected 
	storedToken := session.Values["accessToken"]
	storedGPlusId := session.Values["gplusID"]
	if storedToken != nil && storedGPlusId == gplusID {
		m := "Current user already connected"
		return &appError{errors.New(m), m, http.StatusOK}
	}

	// Store the access token in the session for later use 
	session.Values["accessToken"] = accessToken
	session.Values["gplusID"] = gplusID
	session.Save(r, w)
	return nil
}

// disconnect revokes the current user's token and resets theri session
func disconnect(w http.ResponseWriter, r *http.Request) *appError {
	// Only disconnect a connected user 
	session, err := store.Get(r, "sessionName")
	if err != nil {
		log.Println("error fetching session:", err)
		return &appError{err, "Error fetching session", http.StatusInternalServerError}
	}
	token := session.Values["accessToken"]
	if token == nil {
		m := "Current user not connected"
		return &appError{errors.New(m), m, http.StatusUnauthorized}
	}

	// Execute HTTP GET request to revoke current token
	url := "https://accounts.google.com/o/oauth2/revoke?token=" + token.(string)
	resp, err := http.Get(url)
	if err != nil {
		m := "Failed to revoke token for a given user"
		return &appError{errors.New(m), m, http.StatusBadRequest}
	}
	defer resp.Body.Close()

	// Reset the user's session
	session.Values["accessToken"] = nil
	session.Save(r, w)
	return nil
}

func people(w http.ResponseWriter, r *http.Request) *appError {
	session, err := store.Get(r, "sessionName")
	if err != nil {
		log.Println("error fetching session:", err)
		return &appError{err, "Error fetching session", http.StatusInternalServerError}
	}
	token := session.Values["accessToken"]
	// Only fetch a list of people for connected users
	if token == nil {
		m := "Current user not connected"
		return &appError{errors.New(m), m, http.StatusUnauthorized}
	}

	// Create a new authorized API client 
	t := &oauth.Transport{Config: config}
	tok := new(oauth.Token)
	tok.AccessToken = token.(string)
	t.Token = tok
	service, err := plus.New(t.Client())
	if err != nil {
		return &appError{err, "Create Plus Client", http.StatusInternalServerError}
	}

	// Get a list of people that this user has shared with this app
	people := service.People.List("me", "visible")
	peopleFeed, err := people.Do()
	if err != nil {
		m := "Failed to refresh access token"
		if err.Error() == "AccessTokenRefreshError" {
			return &appError{errors.New(m), m, http.StatusInternalServerError}
		}
		return &appError{err, m, http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(&peopleFeed)
	if err != nil {
		return &appError{err, "Convert PeopleFeed to JSON", http.StatusInternalServerError}
	}
	return nil
}

// index sets up a session for the current user and serves the index page.
func index(w http.ResponseWriter, r *http.Request) *appError {
	// index should only ever respond to "/" exactly, it's not a catch all
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return nil
	}

	log.Printf("Responding to request %s with index handler.%v", r.URL, lineEnding)

	// Create a state token to prevent request forgery and store it in the 
	// session for later validation. 
	session, err := store.Get(r, "sessionName")
	if err != nil {
		log.Println("error fetching session:", err)
		// Ignore the initial session fetch error, as Get() returns a 
		// session even if empty.
		if !session.IsNew {
			return &appError{err, "Error fetching session", 500}
		}
	}
	state := randomString(64)
	session.Values["state"] = state
	session.Save(r, w)

	stateUrl := url.QueryEscape(session.Values["state"].(string))

	// Fill in the missing fields in index.html
	var data = struct {
		ApplicationName, ClientID, State string
	}{applicationName, clientID, stateUrl}

	// Render and serve the HTML
	err = indexTemplate.Execute(w, data)
	if err != nil {
		log.Println("error rendering the template:", err)
		return &appError{err, "Error rendering template", http.StatusInternalServerError}
	}

	log.Printf("Successfully handled request %s.", r.URL)

	return nil
}
