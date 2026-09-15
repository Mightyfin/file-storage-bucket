package party

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExistsUsesCanonicalPartyContract(t *testing.T) {
	for _, body := range []string{`{"party_id":"pty_one","status":"provisional"}`, `{"id":"pty_one"}`, `{"party_id":"other"}`, `{"party_id":"pty_one"} {}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/parties/pty_one" || r.Header.Get("X-Acting-Tenant-Id") != "green" || r.Header.Get("X-Acting-Environment") != "sandbox" {
				t.Error("lost lookup scope")
			}
			w.Write([]byte(body))
		}))
		c := &Client{base: srv.URL, http: srv.Client()}
		err := c.Exists(context.Background(), "green", "sandbox", "pty_one")
		if (err == nil) != (body == `{"party_id":"pty_one","status":"provisional"}`) {
			t.Fatal(body, err)
		}
		srv.Close()
	}
}

func TestExistsRejectsMissingScopeAndRedirect(t *testing.T) {
	c := &Client{}
	for _, args := range [][3]string{{"", "sandbox", "party"}, {"green", "", "party"}, {"green", "sandbox", ""}} {
		if c.Exists(context.Background(), args[0], args[1], args[2]) == nil {
			t.Fatal("missing scope accepted")
		}
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Redirect(w, r, "/other", 302) }))
	defer srv.Close()
	c, err := New(context.Background(), srv.URL, "", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Exists(context.Background(), "green", "sandbox", "party") == nil || calls != 1 {
		t.Fatal("followed redirect", calls)
	}
}
