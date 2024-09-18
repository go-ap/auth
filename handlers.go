package auth

import (
	"net/http"

	"github.com/go-ap/errors"
)

func (s *Server) ValidateLoggedIn() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if !s.account.IsLogged() {
				e := errors.Unauthorizedf("Please login to perform this action")
				s.l.Errorf("%s", e)
				errors.HandleError(e).ServeHTTP(w, r)
				http.Redirect(w, r, "/login", http.StatusMovedPermanently)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
