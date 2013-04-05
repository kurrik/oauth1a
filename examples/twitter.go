package main

import (
	".." // Use "github.com/kurrik/oauth1a" in your code
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var (
	settings *Settings
	service  *oauth1a.Service
	sessions map[string]*oauth1a.UserConfig
)

func NewSessionID() string {
	c := 128
	b := make([]byte, c)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		panic("Could not generate random number")
	}
	return base64.URLEncoding.EncodeToString(b)
}

func GetSessionID(req *http.Request) (id string, err error) {
	var c *http.Cookie
	if c, err = req.Cookie("session_id"); err != nil {
		return
	}
	id = c.Value
	return
}

func SessionStartCookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:   "session_id",
		Value:  id,
		MaxAge: 60,
		Secure: false,
		Path:   "/",
	}
}

func SessionEndCookie() *http.Cookie {
	return &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: 0,
		Secure: false,
		Path:   "/",
	}
}

func BaseHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(rw, "<a href=\"/signin\">Sign in</a>")
}

func SignInHandler(rw http.ResponseWriter, req *http.Request) {
	var (
		url       string
		err       error
		sessionID string
	)
	httpClient := new(http.Client)
	userConfig := &oauth1a.UserConfig{}
	if err = userConfig.GetRequestToken(service, httpClient); err != nil {
		log.Printf("Could not get request token: %v", err)
		http.Error(rw, "Problem getting the request token", 500)
		return
	}
	if url, err = userConfig.GetAuthorizeURL(service); err != nil {
		log.Printf("Could not get authorization URL: %v", err)
		http.Error(rw, "Problem getting the authorization URL", 500)
		return
	}
	log.Printf("Redirecting user to %v\n", url)
	sessionID = NewSessionID()
	log.Printf("Starting session %v\n", sessionID)
	sessions[sessionID] = userConfig
	http.SetCookie(rw, SessionStartCookie(sessionID))
	http.Redirect(rw, req, url, 302)
}

func CallbackHandler(rw http.ResponseWriter, req *http.Request) {
	var (
		err        error
		token      string
		verifier   string
		sessionID  string
		userConfig *oauth1a.UserConfig
		ok         bool
	)
	log.Printf("Callback hit. %v current sessions.\n", len(sessions))
	if sessionID, err = GetSessionID(req); err != nil {
		log.Printf("Got a callback with no session id: %v\n", err)
		http.Error(rw, "No session found", 400)
		return
	}
	if userConfig, ok = sessions[sessionID]; !ok {
		log.Printf("Could not find user config in sesions storage.")
		http.Error(rw, "Invalid session", 400)
		return
	}
	if token, verifier, err = userConfig.ParseAuthorize(req, service); err != nil {
		log.Printf("Could not parse authorization: %v", err)
		http.Error(rw, "Problem parsing authorization", 500)
		return
	}
	httpClient := new(http.Client)
	if err = userConfig.GetAccessToken(token, verifier, service, httpClient); err != nil {
		log.Printf("Error getting access token: %v", err)
		http.Error(rw, "Problem getting an access token", 500)
		return
	}
	log.Printf("Ending session %v.\n", sessionID)
	delete(sessions, sessionID)
	http.SetCookie(rw, SessionEndCookie())
	rw.Header().Set("Content-Type", "text/html;charset=utf-8")
	fmt.Fprintf(rw, "<pre>")
	fmt.Fprintf(rw, "Access Token: %v\n", userConfig.AccessTokenKey)
	fmt.Fprintf(rw, "Token Secret: %v\n", userConfig.AccessTokenSecret)
	fmt.Fprintf(rw, "Screen Name:  %v\n", userConfig.AccessValues.Get("screen_name"))
	fmt.Fprintf(rw, "User ID:      %v\n", userConfig.AccessValues.Get("user_id"))
	fmt.Fprintf(rw, "</pre>")
	fmt.Fprintf(rw, "<a href=\"/signin\">Sign in again</a>")
}

type Settings struct {
	Key  string
	Sec  string
	Port int
}

func main() {
	sessions = map[string]*oauth1a.UserConfig{}
	settings = &Settings{}
	flag.IntVar(&settings.Port, "port", 10000, "Port to run on")
	flag.StringVar(&settings.Key, "key", "", "Consumer key of your app")
	flag.StringVar(&settings.Sec, "secret", "", "Consumer secret of your app")
	flag.Parse()
	if settings.Key == "" || settings.Sec == "" {
		fmt.Fprintf(os.Stderr, "You must specify a consumer key and secret.\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	service = &oauth1a.Service{
		RequestURL:   "https://api.twitter.com/oauth/request_token",
		AuthorizeURL: "https://api.twitter.com/oauth/authorize",
		AccessURL:    "https://api.twitter.com/oauth/access_token",
		ClientConfig: &oauth1a.ClientConfig{
			ConsumerKey:    settings.Key,
			ConsumerSecret: settings.Sec,
			CallbackURL:    "http://localhost:10000/callback/",
		},
		Signer: new(oauth1a.HmacSha1Signer),
	}

	http.HandleFunc("/", BaseHandler)
	http.HandleFunc("/signin/", SignInHandler)
	http.HandleFunc("/callback/", CallbackHandler)
	log.Printf("Visit http://localhost:%v in your browser\n", settings.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", settings.Port), nil))
}
