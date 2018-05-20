package pwned

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	filter := NewFilter(4, 2)
	filter.AddHash(apple)
	filter.AddHash(orange)

	logger := &log.Logger{}
	logger.SetOutput(ioutil.Discard)
	h := Handler{Filter: filter, Logger: logger}

	t.Run("404s on no hash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)

		if res.Code != http.StatusNotFound {
			t.Errorf("got %d, expected %d", res.Code, http.StatusNotFound)
		}
	})

	t.Run("400s when hash isn't the right length", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/aaa", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("got %d, expected %d", res.Code, http.StatusBadRequest)
		}
	})

	t.Run("400s when hash isn't valid hex", func(t *testing.T) {
		// 'P' is the first character
		req := httptest.NewRequest(http.MethodGet, "/P0be2dc421be4fcd0172e5afceea3970e2f3d940", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("got %d, expected %d", res.Code, http.StatusBadRequest)
		}
	})

	t.Run("404s when hash was not found", func(t *testing.T) {
		// pear
		req := httptest.NewRequest(http.MethodGet, "/3e2bf5faa2c3fec1f84068a073b7e51d7ad44a35/", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)

		if res.Code != http.StatusNotFound {
			t.Errorf("got %d, expected %d", res.Code, http.StatusNotFound)
		}
		if res.Body.String() != "OK" {
			t.Errorf("got %s, expected \"OK\"", res.Body.String())
		}
	})

	t.Run("200s when hash exists", func(t *testing.T) {
		// orange
		req := httptest.NewRequest(http.MethodGet, "/ef0ebbb77298e1fbd81f756a4efc35b977c93dae/", nil)
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)

		if res.Code != http.StatusOK {
			t.Errorf("got %d, expected %d", res.Code, http.StatusOK)
		}

		if res.Body.String() != "1" {
			t.Errorf("got %q, expected \"1\"", res.Body.String())
		}
	})
}
