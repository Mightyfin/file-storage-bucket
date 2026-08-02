package party

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	base  string
	http  *http.Client
	local bool
}

func New(ctx context.Context, base, tokenURL, id, secret string, local bool) (*Client, error) {
	h := &http.Client{Timeout: 5 * time.Second}
	if tokenURL != "" || id != "" || secret != "" {
		if tokenURL == "" || id == "" || secret == "" {
			return nil, fmt.Errorf("incomplete Party OAuth")
		}
		src := (&clientcredentials.Config{ClientID: id, ClientSecret: secret, TokenURL: tokenURL, Scopes: []string{"party.read"}, AuthStyle: oauth2.AuthStyleInHeader}).TokenSource(ctx)
		h.Transport = &oauth2.Transport{Source: oauth2.ReuseTokenSource(nil, src)}
	} else if !local {
		return nil, fmt.Errorf("Party OAuth required")
	}
	return &Client{strings.TrimRight(base, "/"), h, local}, nil
}
func (c *Client) Exists(ctx context.Context, tenant, environment, id string) error {
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/parties/"+url.PathEscape(id), nil)
	if e != nil {
		return e
	}
	r.Header.Set("X-Acting-Tenant-Id", tenant)
	r.Header.Set("X-Acting-Environment", environment)
	resp, e := c.http.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("party status %d", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); e != nil {
		return e
	}
	if out.ID != id {
		return fmt.Errorf("party mismatch")
	}
	return nil
}
