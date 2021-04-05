package filter

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/RomanLorens/logger/log"
	"github.com/RomanLorens/rl-common/hash"
)

// WhiteList white list config
type WhiteList struct {
	IP        string   `json:"ip"`
	User      string   `json:"user"`
	IsAdmin   bool     `json:"isAdmin"`
	Endpoints []string `json:"endpoints"`
	Token     string   `json:"token"`
}

//Filter filter
type Filter interface {
	DoFilter(r *http.Request) (bool, *http.Request)
}

//BearerTokenIPFilter bearer token ip filter
type BearerTokenIPFilter struct {
	logger log.Logger
	tokens map[string]*WhiteList
	ips    map[string]*WhiteList
}

//NewBearerTokenIPFilter creates filter
func NewBearerTokenIPFilter(l log.Logger, cfg []WhiteList) *BearerTokenIPFilter {
	tokens := make(map[string]*WhiteList)
	ips := make(map[string]*WhiteList)
	for _, c := range cfg {
		tokens[c.User] = &c
		ips[c.IP] = &c
	}
	return &BearerTokenIPFilter{logger: l, tokens: tokens, ips: ips}
}

//DoFilter authenticate by authorization bearer token or ip
func (f BearerTokenIPFilter) DoFilter(r *http.Request) (bool, *http.Request) {
	//localhost
	if strings.Contains(r.RemoteAddr, "[::") {
		return true, r
	}
	bt := bearerToken(r)
	var ipcfg *WhiteList
	if bt != "" {
		f.logger.Info(r.Context(), "BearerTokenIPFilter checking bearer token in whitelist")
		t := strings.Split(bt, "-")
		if len(t) > 0 {
			ipcfg = f.tokens[t[0]]
			if ipcfg != nil {
				ok := hash.Verfify(strings.Join(t[1:], "-"), ipcfg.Token)
				if !ok {
					f.logger.Error(r.Context(), "Invalid bearer token '%v'", bt)
					return false, r
				}
			} else {
				f.logger.Error(r.Context(), "Missing whitelist cfg for user '%v'", t[0])
			}
		} else {
			f.logger.Error(r.Context(), "Invalid bearer format '%v'", bt)
		}
	}

	if ipcfg == nil {
		f.logger.Info(r.Context(), "BearerTokenIPFilter checking ip address %v in whitelist", r.RemoteAddr)
		ipcfg = f.ips[strings.Split(r.RemoteAddr, ":")[0]]
		if ipcfg == nil {
			f.logger.Error(r.Context(), fmt.Sprintf("%v NOT whitelisted ip", r.RemoteAddr))
			return false, r
		}
	}

	isAuthorized := false
	if !ipcfg.IsAdmin {
		for _, url := range ipcfg.Endpoints {
			if strings.Contains(r.URL.String(), url) {
				isAuthorized = true
				break
			}
		}
	} else {
		isAuthorized = true
	}

	if !isAuthorized {
		f.logger.Error(r.Context(), fmt.Sprintf("user '%v' not authorized to endpoint %v, ip = '%v'", ipcfg.User, r.URL.String(), r.RemoteAddr))
		return false, r
	}
	ctx := context.WithValue(r.Context(), log.UserKey, ipcfg.User+"-ip")
	r = r.WithContext(ctx)
	f.logger.Info(r.Context(), fmt.Sprintf("'%v' is whitelisted for user '%v'", r.RemoteAddr, ipcfg.User))
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

func (w WhiteList) String() string {
	return fmt.Sprintf("{user: '%v', ip: '%v', token: '%v', admin: %v, endpoints: %v}", w.User, w.IP, w.Token, w.IsAdmin, w.Endpoints)
}
