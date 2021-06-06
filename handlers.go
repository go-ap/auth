package auth

import (
	"encoding/json"
	"net/http"

	"github.com/go-ap/errors"
	"github.com/openshift/osin"
	"github.com/sirupsen/logrus"
)

func (s *Server) Redirect(w http.ResponseWriter, r *http.Request, url string, status int) {
	if err := s.saveSession(w, r); err != nil {
		s.l.WithFields(logrus.Fields{
			"status": status,
			"url":    url,
		}).Error(err.Error())
	}

	http.Redirect(w, r, url, status)
}

func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	os := s.Server

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

// Token
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	os := s.Server
	resp := os.NewResponse()
	defer resp.Close()

	if ar := os.HandleAccessRequest(resp, r); ar != nil {
		if who, ok := ar.UserData.(json.RawMessage); ok {
			if err := json.Unmarshal(who, &s.account); err == nil {
				ar.Authorized = s.account.IsLogged()
			} else {
				s.l.Errorf("%s", err)
			}
		}
		os.FinishAccessRequest(resp, r, ar)
	}
	redirectOrOutput(resp, w, r, s)
}

func redirectOrOutput(rs *osin.Response, w http.ResponseWriter, r *http.Request, s *Server) {
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
