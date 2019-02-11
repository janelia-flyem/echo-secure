package secure

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	uuid "github.com/satori/go.uuid"
	"time"
)

const (
	defaultSessionID = "neuPrintHTTP"
	// The following keys are used for the default session. For example:
	//  session, _ := bookshelf.SessionStore.New(r, defaultSessionID)
	//  session.Values[oauthTokenSessionKey]
	googleProfileSessionKey = "google_profile"
	oauthTokenSessionKey    = "oauth_token"

	// This key is used in the OAuth flow session to store the URL to redirect the
	// user to after the OAuth flow is complete.
	oauthFlowRedirectKey = "redirect"

	AlgorithmHS256 = "HS256"

	COOKIEEXPIRE = 86400 * 30
)

// global to hold oauth configuration
var OAuthConfig *oauth2.Config
var JWTSecret []byte

func init() {
	// Gob encoding for gorilla/sessions
	gob.Register(&oauth2.Token{})
	gob.Register(&Profile{})
}

func configureOAuthClient(clientID, clientSecret, url string) {
	OAuthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  url,
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}
}

type jwtCustomClaims struct {
	Email    string `json:"email"`
	Level    string `json:"level"`
	ImageURL string `json:"image-url"`
	jwt.StandardClaims
}

// loginHandler initiates an OAuth flow to authenticate the user.
func loginHandler(c echo.Context) error {
	sessionID := uuid.Must(uuid.NewV4()).String()
	r := c.Request()
	w := c.Response()

	auto := c.QueryParam("auto")
	if auto == "true" {
		// check if already logged in
		if currSession, err := session.Get(defaultSessionID, c); err == nil {
			if profile, ok := currSession.Values[googleProfileSessionKey].(*Profile); ok && profile != nil {
				currSession.Save(c.Request(), c.Response())
				// there should be no redirect url if called in auto mode
				return c.Redirect(http.StatusFound, "/profile")
			}
		}
	}

	oauthFlowSession, err := session.Get(sessionID, c)
	if err != nil {
		return fmt.Errorf("could not create oauth session: %v", err)
	}
	oauthFlowSession.Options = &sessions.Options{
		MaxAge:   600,
		HttpOnly: true,
	}

	redirectURL, err := validateRedirectURL(c.FormValue("redirect"))
	if err != nil {
		return fmt.Errorf("invalid redirect URL: %v", err)
	}
	oauthFlowSession.Values[oauthFlowRedirectKey] = redirectURL

	if err := oauthFlowSession.Save(r, w); err != nil {
		return fmt.Errorf("could not save session: %v", err)
	}

	// Use the session ID for the "state" parameter.
	// This protects against CSRF (cross-site request forgery).
	// See https://godoc.org/golang.org/x/oauth2#Config.AuthCodeURL for more detail.
	url := OAuthConfig.AuthCodeURL(sessionID, oauth2.AccessTypeOnline)
	return c.Redirect(http.StatusFound, url)
}

// validateRedirectURL checks that the URL provided is valid.
// If the URL is missing, redirect the user to the application's root.
// The URL must not be absolute (i.e., the URL must refer to a path within this
// application).
func validateRedirectURL(path string) (string, error) {
	if path == "" {
		return "/profile", nil
	}

	// Ensure redirect URL is valid and not pointing to a different server.
	parsedURL, err := url.Parse(path)
	if err != nil {
		return "/profile", err
	}
	if parsedURL.IsAbs() {
		return "/profile", errors.New("URL must not be absolute")
	}
	return path, nil
}

// oauthCallbackHandler completes the OAuth flow, retreives the user's profile
// information and stores it in a session.
func oauthCallbackHandler(c echo.Context) error {
	oauthFlowSession, err := session.Get(c.FormValue("state"), c)
	if err != nil {
		return fmt.Errorf("invalid state parameter. try logging in again.")
	}

	redirectURL, ok := oauthFlowSession.Values[oauthFlowRedirectKey].(string)
	// Validate this callback request came from the app.
	if !ok {
		return fmt.Errorf("invalid state parameter. try logging in again.")
	}

	code := c.FormValue("code")
	tok, err := OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return fmt.Errorf("could not get auth token: %v", err)
	}

	sessionNew, err := session.Get(defaultSessionID, c)
	if err != nil {
		return fmt.Errorf("could not get default session: %v", err)
	}

	ctx := context.Background()
	profile, err := fetchProfile(ctx, tok)
	if err != nil {
		return fmt.Errorf("could not fetch Google profile: %v", err)
	}

	sessionNew.Values[oauthTokenSessionKey] = tok
	// Strip the profile to only the fields we need. Otherwise the struct is too big.
	sessionNew.Values[googleProfileSessionKey] = stripProfile(profile)
	if err := sessionNew.Save(c.Request(), c.Response()); err != nil {
		return fmt.Errorf("could not save session: %v", err)
	}

	return c.Redirect(http.StatusFound, redirectURL)
}

type userInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

// fetchProfile retrieves the Google+ profile of the user associated with the
// provided OAuth token.
func fetchProfile(ctx context.Context, tok *oauth2.Token) (*userInfo, error) {
	client := oauth2.NewClient(ctx, OAuthConfig.TokenSource(ctx, tok))

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result userInfo
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// logoutHandler clears the default session.
func logoutHandler(c echo.Context) error {
	currSession, err := session.Get(defaultSessionID, c)
	if err != nil {
		return fmt.Errorf("could not get default session: %v", err)
	}
	currSession.Options.MaxAge = -1 // Clear session.
	if err := currSession.Save(c.Request(), c.Response()); err != nil {
		return fmt.Errorf("could not save session: %v", err)
	}
	redirectURL := c.FormValue("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}

	return c.HTML(http.StatusOK, "")
}

// profileFromSession retreives the Google+ profile from the default session.
// Returns nil if the profile cannot be retreived (e.g. user is logged out).
func profileFromSession(c echo.Context) *Profile {
	user, ok := c.Get("user").(*jwt.Token)
	if ok {
		claims := user.Claims.(*jwtCustomClaims)
		email := claims.Email
		url := claims.ImageURL
		return &Profile{email, url}
	}

	currSession, err := session.Get(defaultSessionID, c)
	if err != nil {
		return nil
	}
	profile, ok := currSession.Values[googleProfileSessionKey].(*Profile)
	if !ok {
		return nil
	}
	return profile
}

func profileHandler(c echo.Context) error {
	profile := profileFromSession(c)
	level, ok := c.Get("level").(string)
	if !ok {
		level = "noauth"
	}
	profileout := &ProfileAuth{profile, level}
	return c.JSON(http.StatusOK, profileout)
}

func tokenHandler(c echo.Context) error {
	// Set claims
	profile := profileFromSession(c)

	level, ok := c.Get("level").(string)
	if !ok {
		level = "noauth"
	}

	claims := &jwtCustomClaims{
		profile.Email,
		level,
		profile.ImageURL,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 50000).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString(JWTSecret)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{
		"token": t,
	})
}

type Profile struct {
	ImageURL, Email string
}

type ProfileAuth struct {
	*Profile
	AuthLevel string
}

// stripProfile returns a subset of the user profile.
func stripProfile(p *userInfo) *Profile {
	return &Profile{
		ImageURL: p.Picture + "?sz=50",
		Email:    p.Email,
	}
}
