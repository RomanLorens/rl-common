package auth

// WhiteList white list config
type WhiteList struct {
	IP        string   `json:"ip"`
	User      string   `json:"user"`
	IsAdmin   bool     `json:"isAdmin"`
	Endpoints []string `json:"endpoints"`
	Token     string   `json:"token"`
}

var (
	tokens map[string]*WhiteList
	ips    map[string]*WhiteList
)

//New Inits configuration
func New(config []WhiteList) {
	for _, c := range config {
		tokens[c.Token] = &c
		ips[c.IP] = &c
	}
}

//GetByToken get config by token
func GetByToken(t string) *WhiteList {
	return tokens[t]
}

//GetByIP get config by ip
func GetByIP(i string) *WhiteList {
	return ips[i]
}
