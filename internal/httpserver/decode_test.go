package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownAndTrailingJSON(t *testing.T) {
	for _, body := range []string{`{"name":"valid","unknown":true}`, `{"name":"one"}{"name":"two"}`} {
		request := httptest.NewRequest("POST", "/", strings.NewReader(body))
		var destination struct {
			Name string `json:"name"`
		}
		if err := decode(request, &destination); err == nil {
			t.Errorf("ambiguous body accepted: %q", body)
		}
	}
}
