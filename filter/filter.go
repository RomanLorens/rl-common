package filter

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/RomanLorens/logger/log"
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

//WhiteListedEndpointFilter whitelisted endpoints
type WhiteListedEndpointFilter struct {
	endpoints []string
}

func NewWhiteListedEndpointFilter(endpoints []string) *WhiteListedEndpointFilter {
	return &WhiteListedEndpointFilter{endpoints: endpoints}
}

//NewBearerTokenIPFilter creates filter
func NewBearerTokenIPFilter(l log.Logger, cfg []WhiteList) *BearerTokenIPFilter {
	tokens := make(map[string]*WhiteList)
	ips := make(map[string]*WhiteList)
	for _, c := range cfg {
		tokens[c.Token] = &c
		ips[c.IP] = &c
	}
	return &BearerTokenIPFilter{logger: l, tokens: tokens, ips: ips}
}

//DoFilter checks if url is whitelisted
func (f WhiteListedEndpointFilter) DoFilter(r *http.Request) (bool, *http.Request) {
	for _, e := range f.endpoints {
		if strings.Contains(r.URL.String(), e) {
			return true, r
		}
	}
	return false, r
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
		f.logger.Info(r.Context(), "AuthenticatedIPFilter checking bearer token in whitelist")
		ipcfg = f.tokens[bt]
	} else {
		f.logger.Info(r.Context(), "AuthenticatedIPFilter checking ip address %v in whitelist", r.RemoteAddr)
		ipcfg = f.ips[strings.Split(r.RemoteAddr, ":")[0]]
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
