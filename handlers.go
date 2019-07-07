package auth

import (
	"encoding/json"
	"fmt"
	"github.com/go-ap/errors"
	"github.com/go-chi/chi"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"strings"
	"time"
)

type OAuth struct {
	Provider     string
	Code         string
	Token        string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	State        string
}

	// HandleCallback serves /auth/{provider}/callback request
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := chi.URLParam(r, "provider")
	providerErr := q["error"]
	if providerErr != nil {
		err := errors.Errorf("Error for provider %q: %s", provider,  q["error_description"])
		errors.HandleError(err).ServeHTTP(w, r)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if len(code) == 0 {
		err := errors.Forbiddenf("%s error: Empty authentication token", provider)
		errors.HandleError(err).ServeHTTP(w, r)
		return
	}

	conf := GetOauth2Config(provider, s.baseURL)
	tok, err := conf.Exchange(r.Context(), code)
	if err != nil {
		s.l.Errorf("%s", err)
		errors.HandleError(err).ServeHTTP(w,r)
		return
	}
	s.l.WithFields(logrus.Fields{
		"token": tok,
		"state": state,
		"code": code,
	}).Infof("OAuth success")
	//oauth := OAuth{
	//	State:        state,
	//	Code:         code,
	//	Provider:     provider,
	//	Token:        tok.AccessToken,
	//	TokenType:    tok.TokenType,
	//	RefreshToken: tok.RefreshToken,
	//	Expiry:       tok.Expiry,
	//}
	//sess, _ := s.sstor.Get(r, sessionName)
	//h.account = loadCurrentAccountFromSession(s, h.logger)
	//s.Values[SessionUserKey] = sessionAccount{
	//	Handle: h.account.Handle,
	//	Hash:   []byte(h.account.Hash),
	//	OAuth:  oauth,
	//}
	//if strings.ToLower(provider) != "local" {
	//	h.addFlashMessage(Success, r, fmt.Sprintf("Login successful with %s", provider))
	//} else {
	//	h.addFlashMessage(Success, r, "Login successful")
	//}
	s.Redirect(w, r, "/", http.StatusFound)
}

func GetOauth2Config(provider string, localBaseURL string) oauth2.Config {
	 config := oauth2.Config{
		ClientID:     os.Getenv("OAUTH2_KEY"),
		ClientSecret: os.Getenv("OAUTH2_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/oauth/authorize", localBaseURL),
			TokenURL: fmt.Sprintf("%s/oauth/token", localBaseURL),
		},
	}
	url := os.Getenv("OAUTH2_URL")
	if url == "" {
		url = fmt.Sprintf("%s/auth/%s/callback", localBaseURL, provider)
	}
	config.RedirectURL = url
	return config
}

// HandleAuth serves /auth/{provider} request
func (s *Server) HandleAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	indexUrl := "/"
	if strings.ToLower(provider) != "local" && os.Getenv("OAUTH2_KEY") == "" {
		s.l.WithFields(logrus.Fields{
			"provider": provider,
		}).Info("Provider has no credentials set")
		s.Redirect(w, r, indexUrl, http.StatusPermanentRedirect)
		return
	}

	// TODO(marius): generated _CSRF state value to check in h.HandleCallback
	config := GetOauth2Config(provider, s.baseURL)
	//if len(config.ClientID) == 0 {
	//	s, err := h.sstor.Get(r, sessionName)
	//	if err != nil {
	//		h.logger.Debugf(err.Error())
	//	}
	//	s.AddFlash("Missing oauth provider")
	//	h.Redirect(w, r, indexUrl, http.StatusPermanentRedirect)
	//}
	// redirURL := "http://brutalinks.git/oauth/authorize?access_type=online&client_id=eaca4839ddf16cb4a5c4ca126db8de5c&redirect_uri=http%3A%2F%2Fbrutalinks.git%2Fauth%2Flocal%2Fcallback&response_type=code&state=state"
	s.Redirect(w, r, config.AuthCodeURL("state", oauth2.AccessTypeOnline), http.StatusFound)
}

func (s *Server) Redirect(w http.ResponseWriter, r *http.Request, url string, status int) {
	//if err := h.saveSession(w, r); err != nil {
	//	h.logger.WithContext(log.Ctx{
	//		"status": status,
	//		"url":    url,
	//	}).Error(err.Error())
	//}

	http.Redirect(w, r, url, status)
}


func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	os := s.os

	resp := os.NewResponse()
	defer resp.Close()

	if ar := os.HandleAuthorizeRequest(resp, r); ar != nil {
		if s.account.IsLogged() {
			ar.Authorized = true
			b, _ := json.Marshal(s.account)
			ar.UserData = b
		}
		os.FinishAuthorizeRequest(resp, r, ar)
	}
	redirectOrOutput(resp, w, r, s)
}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	os := s.os
	resp := os.NewResponse()
	defer resp.Close()

	if ar := os.HandleAccessRequest(resp, r); ar != nil {
		if who, ok := ar.UserData.(json.RawMessage); ok {
			if err := json.Unmarshal(who, &s.account); err == nil {
				ar.Authorized = s.account.IsLogged()
			} else {
				s.l.Errorf("%os", err)
			}
		}
		os.FinishAccessRequest(resp, r, ar)
	}
	redirectOrOutput(resp, w, r, s)
}

func redirectOrOutput (rs *osin.Response, w http.ResponseWriter, r *http.Request, s *Server) {
	// Add headers
	for i, k := range rs.Headers {
		for _, v := range k {
			w.Header().Add(i, v)
		}
	}

	if rs.Type == osin.REDIRECT {
		// Output redirect with parameters
		u, err := rs.GetRedirectUrl()
		if err != nil {
			errors.HandleError(err).ServeHTTP(w, r)
			return
		}
		s.Redirect(w, r, u, http.StatusFound)
	} else {
		// set content type if the response doesn't already have one associated with it
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(rs.StatusCode)

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(rs.Output); err != nil {
			errors.HandleError(err).ServeHTTP(w, r)
			return
		}
		if err := s.saveSession(w, r); err != nil {
			errors.HandleError(err).ServeHTTP(w, r)
			return
		}
	}
}

func (s *Server) ValidateLoggedIn() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if !s.account.IsLogged() {
				e := errors.Unauthorizedf("Please login to perform this action")
				s.l.Errorf("%s", e)
				errors.HandleError(e).ServeHTTP(w, r)
				s.Redirect(w, r, "/login", http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func (s *Server) saveSession(w http.ResponseWriter, r *http.Request) error {
	//if s.sstor == nil {
	//	err := errors.New("missing session store, unable to save session")
	//	s.l.Errorf("%sess", err)
	//	return err
	//}
	//sess, err := s.sstor.Get(r, sessionName)
	//if err != nil {
	//	s.l.Errorf("%sess", err)
	//	return errors.Errorf("failed to load session before redirect: %sess", err)
	//}
	//if err := s.sstor.Save(r, w, sess); err != nil {
	//	err := errors.Errorf("failed to save session before redirect: %sess", err)
	//	s.l.Errorf("%sess", err)
	//	return err
	//}
	return nil
}
