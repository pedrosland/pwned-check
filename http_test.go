package pwned

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testHandlerCommon(t *testing.T, fn http.HandlerFunc) {
	t.Run("NoHash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		fn(res, req)

		if res.Code != http.StatusNotFound {
			t.Errorf("got %d, expected %d", res.Code, http.StatusNotFound)
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/aaa", nil)
		res := httptest.NewRecorder()
		fn(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("got %d, expected %d", res.Code, http.StatusBadRequest)
		}
	})

	t.Run("InvalidHex", func(t *testing.T) {
		// 'P' is the first character
		req := httptest.NewRequest(http.MethodGet, "/P0be2dc421be4fcd0172e5afceea3970e2f3d940", nil)
		res := httptest.NewRecorder()
		fn(res, req)

		if res.Code != http.StatusBadRequest {
			t.Errorf("got %d, expected %d", res.Code, http.StatusBadRequest)
		}
	})
}

func TestCompatHandler(t *testing.T) {
	filter := NewFilter(4, 2)
	filter.AddHash(apple)
	filter.AddHash(orange)

	logger := &log.Logger{}
	logger.SetOutput(ioutil.Discard)
	h := Handler{Filter: filter, Logger: logger}

	testHandlerCommon(t, http.HandlerFunc(h.CompatPassword))

	t.Run("NotPwnedHash", func(t *testing.T) {
		// pear
		req := httptest.NewRequest(http.MethodGet, "/3e2bf5faa2c3fec1f84068a073b7e51d7ad44a35/", nil)
		res := httptest.NewRecorder()
		h.CompatPassword(res, req)

		if res.Code != http.StatusNotFound {
			t.Errorf("got %d, expected %d", res.Code, http.StatusNotFound)
		}
		if res.Body.String() != "OK" {
			t.Errorf("got %s, expected \"OK\"", res.Body.String())
		}
	})

	t.Run("PwnedHash", func(t *testing.T) {
		// orange
		req := httptest.NewRequest(http.MethodGet, "/ef0ebbb77298e1fbd81f756a4efc35b977c93dae/", nil)
		res := httptest.NewRecorder()
		h.CompatPassword(res, req)

		if res.Code != http.StatusOK {
			t.Errorf("got %d, expected %d", res.Code, http.StatusOK)
		}

		if res.Body.String() != "1" {
			t.Errorf("got %q, expected \"1\"", res.Body.String())
		}
	})
}

func TestHashHandler(t *testing.T) {
	filter := NewFilter(4, 2)
	filter.AddHash(apple)
	filter.AddHash(orange)

	logger := &log.Logger{}
	logger.SetOutput(ioutil.Discard)
	h := Handler{Filter: filter, Logger: logger}

	testHandlerCommon(t, http.HandlerFunc(h.Hash))

	type jsonResponse struct {
		DefinatelyPwned string
	}

	t.Run("NotPwnedHash", func(t *testing.T) {
		// pear
		req := httptest.NewRequest(http.MethodGet, "/3e2bf5faa2c3fec1f84068a073b7e51d7ad44a35/", nil)
		res := httptest.NewRecorder()
		h.Hash(res, req)

		if res.Code != http.StatusOK {
			t.Errorf("got %d, expected %d", res.Code, http.StatusOK)
		}

		data := jsonResponse{}
		err := json.Unmarshal(res.Body.Bytes(), &data)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if data.DefinatelyPwned != "no" {
			t.Errorf("got %q, expected \"no\"", data.DefinatelyPwned)
		}
	})

	t.Run("PwnedPassword", func(t *testing.T) {
		// orange
		req := httptest.NewRequest(http.MethodGet, "/ef0ebbb77298e1fbd81f756a4efc35b977c93dae/", nil)
		res := httptest.NewRecorder()
		h.Hash(res, req)

		if res.Code != http.StatusOK {
			t.Errorf("got %d, expected %d", res.Code, http.StatusOK)
		}

		data := jsonResponse{}
		err := json.Unmarshal(res.Body.Bytes(), &data)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if data.DefinatelyPwned != "probably" {
			t.Errorf("got %q, expected \"probably\"", data.DefinatelyPwned)
		}
	})
}
