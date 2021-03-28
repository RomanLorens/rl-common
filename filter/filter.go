package filter

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/RomanLorens/logger/log"
	"github.com/RomanLorens/rl-common/auth"
)

//Filter filter
type Filter interface {
	DoFilter(r *http.Request) (bool, *http.Request)
}

//BearerTokenIPFilter bearer token ip filter
type BearerTokenIPFilter struct {
	logger log.Logger
}

//NewBearerTokenIPFilter creates filter
func NewBearerTokenIPFilter(l log.Logger) *BearerTokenIPFilter {
	return &BearerTokenIPFilter{logger: l}
}

//DoFilter authenticate by authorization bearer token or ip
func (f BearerTokenIPFilter) DoFilter(r *http.Request) (bool, *http.Request) {
	//localhost
	if strings.Contains(r.RemoteAddr, "[::") {
		return true, r
	}
	bt := bearerToken(r)
	var ipcfg *auth.WhiteList
	if bt != "" {
		f.logger.Info(r.Context(), "AuthenticatedIPFilter checking bearer token in whitelist")
		ipcfg = auth.GetByToken(bt)
	} else {
		f.logger.Info(r.Context(), "AuthenticatedIPFilter checking ip address %v in whitelist", r.RemoteAddr)
		ipcfg = auth.GetByIP(strings.Split(r.RemoteAddr, ":")[0])
	}
	if ipcfg == nil {
		f.logger.Error(r.Context(), fmt.Sprintf("%v NOT whitelisted ip", r.RemoteAddr))
		return false, r
	}

	isAuthed := false
	if !ipcfg.IsAdmin {
		for _, url := range ipcfg.Endpoints {
			if strings.Contains(r.URL.String(), url) {
				isAuthed = true
				break
			}
		}
	} else {
		isAuthed = true
	}

	if !isAuthed {
		f.logger.Error(r.Context(), fmt.Sprintf("ip address not authenticated as admin to endpoint %v", r.URL.String()))
		return false, r
	}
	ctx := context.WithValue(r.Context(), log.UserKey, ipcfg.User+"-ip")
	r = r.WithContext(ctx)
	f.logger.Info(r.Context(), fmt.Sprintf("%v is whitelisted - user %v", r.RemoteAddr, ipcfg.User))
	return true, r
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	b := strings.Split(auth, "Bearer ")
	if len(b) == 2 {
		return b[1]
	}
	return ""
}
