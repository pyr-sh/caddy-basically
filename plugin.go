package basically

import (
	"crypto/subtle"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("basically", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
	httpserver.RegisterDevDirective("basically", "reauth")
}

type middleware struct {
	config []Config
	next   httpserver.Handler
}

type Config struct {
	manifestPath string
	path         []string
	rules        []Rule
	manifest     Manifest
}

type Rule struct {
	appliesToKind  string
	appliesToValue string
	methods        []string
}

type Manifest struct {
	Users  map[string]string   `json:"users"`
	Groups map[string][]string `json:"groups"`

	userToGroups map[string][]string
}

func parseConfiguration(c *caddy.Controller) ([]Config, error) {
	var configs []Config
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 0 {
			return nil, c.ArgErr()
		}

		config, err := parseBlock(c)
		if err != nil {
			return nil, err
		}

		configs = append(configs, config)
	}
	return configs, nil
}

func parseBlock(c *caddy.Controller) (Config, error) {
	r := Config{}
	for c.NextBlock() {
		switch c.Val() {
		case "manifest":
			// 1 arg, path to the file
			if !c.NextArg() {
				return r, c.ArgErr()
			}
			r.manifestPath = c.Val()
			if c.NextArg() {
				return r, c.ArgErr()
			}

			manifestBytes, err := ioutil.ReadFile(r.manifestPath)
			if err != nil {
				return r, err
			}
			var manifest Manifest
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				return r, err
			}
			manifest.userToGroups = map[string][]string{}
			for group, users := range manifest.Groups {
				for _, user := range users {
					if _, ok := manifest.userToGroups[user]; ok {
						manifest.userToGroups[user] = append(
							manifest.userToGroups[user], group,
						)
					} else {
						manifest.userToGroups[user] = []string{group}
					}
				}
			}
			r.manifest = manifest
		case "path":
			// 1 arg,
			if !c.NextArg() {
				return r, c.ArgErr()
			}
			r.path = append(r.path, c.Val())
			if c.NextArg() {
				return r, c.ArgErr()
			}
		case "authenticated":
			var rule Rule
			rule.appliesToKind = "authenticated"
			for c.NextArg() {
				rule.methods = append(rule.methods, c.Val())
			}
			r.rules = append(r.rules, rule)
		case "group":
			// 1st arg is the group name
			if !c.NextArg() {
				return r, c.ArgErr()
			}

			var rule Rule
			rule.appliesToKind = "group"
			rule.appliesToValue = c.Val()
			for c.NextArg() {
				rule.methods = append(rule.methods, c.Val())
			}
			r.rules = append(r.rules, rule)
		}
	}

	return r, nil
}

func setup(c *caddy.Controller) error {
	config, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	s := httpserver.GetConfig(c)
	s.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &middleware{
			config: config,
			next:   next,
		}
	})
	return nil
}

func (m *middleware) basicAuth(w http.ResponseWriter, realm string) (int, error) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	return http.StatusUnauthorized, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return m.basicAuth(w, "Please log in")
	}

	for _, c := range m.config {
		var protecting bool
		for _, pp := range c.path {
			if httpserver.Path(r.URL.Path).Matches(pp) {
				protecting = true
				break
			}
		}
		if !protecting {
			continue
		}

		desiredPassword, ok := c.manifest.Users[username]
		if !ok ||
			subtle.ConstantTimeCompare(
				[]byte(desiredPassword),
				[]byte(password),
			) != 1 {
			return m.basicAuth(w, "Invalid password "+username+" - "+password)
		}

		groups := c.manifest.userToGroups[username]

		var matched bool
	rulesLoop:
		for _, rule := range c.rules {
			var foundMethod bool
			for _, method := range rule.methods {
				if method == r.Method {
					foundMethod = true
					break
				}
			}
			if !foundMethod {
				continue
			}

			switch rule.appliesToKind {
			case "authenticated":
				matched = true
				break
			case "group":
				for _, group := range groups {
					if group == rule.appliesToValue {
						matched = true
						break rulesLoop
					}
				}
			}
		}

		if !matched {
			return m.basicAuth(w, "Unauthorized")
		}
	}
	return m.next.ServeHTTP(w, r)
}
