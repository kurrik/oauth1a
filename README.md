# Package oauth1a
## Summary
An implementation of OAuth 1.0a in Go1.

## Installing
Run:

    go get github.com/kurrik/golibs/oauth1a

Include in your source:

    import "github.com/kurrik/golibs/oauth1a"

## Testing
Clone this repository, then run:

    go test -short

in the `oauth1a` directory.  To run an integration test, create a file named
CREDENTIALS in the library directory.  There should be four lines in this file,
in the following format:

    <Twitter consumer key>
    <Twitter consumer secret>
    <Twitter access token>
    <Twitter access token secret>

Then run:

    go test

This will run an integration test against the Twitter
`/account/verify_credentials.json` endpoint.

## Using
The best bet will be to check `oauth1a_test.go` for usage.

As a vague example, here is code to configure the library for accessing Twitter:

    service := &oauth1a.Service{
    	RequestURL:   "https://api.twitter.com/oauth/request_token",
    	AuthorizeURL: "https://api.twitter.com/oauth/request_token",
    	AccessURL:    "https://api.twitter.com/oauth/request_token",
    	ClientConfig: &oauth1a.ClientConfig{
    		ConsumerKey:    "<your Twitter consumer key>",
    		ConsumerSecret: "<your Twitter consumer secret>",
    		CallbackURL:    "<your Twitter callback URL>",
    	},
    	Signer: new(oauth1a.HmacSha1Signer),
    }

To obtain user credentials:

    httpClient := new(http.Client)
    userConfig := &oauth1a.UserConfig{}
    userConfig.GetRequestToken(service, httpClient)
    url, _ := userConfig.GetAuthorizeUrl(service)
    var token string
    var verifier string
    // Redirect the user to <url> and parse out token and verifier from the response.
    userConfig.GetAccessToken(token, verifier, service, httpClient)

Or if you have existing credentials:

    token := "<your access token>"
    secret := "<your access token secret>"
    userConfig := NewAuthorizedConfig(token, secret)

To send an authenticated request:

    httpRequest, _ := http.NewRequest("GET", "https://api.twitter.com/1/account/verify_credentials.json", nil)
    service.Sign(httpRequest, userConfig)
    var httpResponse *http.Response
    var err error
    httpResponse, err = httpClient.Do(httpRequest)



