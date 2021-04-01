package filter

import (
	"net/http"
	"strings"
)

//WhiteListedEndpointFilter whitelisted endpoints
type WhiteListedEndpointFilter struct {
	endpoints []string
}

func NewWhiteListedEndpointFilter(endpoints []string) *WhiteListedEndpointFilter {
	return &WhiteListedEndpointFilter{endpoints: endpoints}
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
