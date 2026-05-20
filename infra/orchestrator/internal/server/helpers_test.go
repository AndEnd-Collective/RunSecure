package server

import (
	"net/http"
	"net/http/httptest"
)

func httpReq(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

func httpRec() *httptest.ResponseRecorder { return httptest.NewRecorder() }
