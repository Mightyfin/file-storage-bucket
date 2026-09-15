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
	h := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
	if tenant == "" || id == "" || (environment != "sandbox" && environment != "production") {
		return fmt.Errorf("explicit party scope required")
	}
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
		PartyID  string `json:"party_id"`
		LegacyID string `json:"id"`
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(data) > 1<<20 {
		return fmt.Errorf("invalid party response")
	}
	if e = json.Unmarshal(data, &out); e != nil {
		return e
	}
	// Older deployed Party releases use id. Accept either exact contract during
	// rollout, but never accept conflicting identities in a mixed response.
	if (out.PartyID == "" && out.LegacyID == "") || (out.PartyID != "" && out.PartyID != id) || (out.LegacyID != "" && out.LegacyID != id) {
		return fmt.Errorf("party mismatch")
	}
	return nil
}
