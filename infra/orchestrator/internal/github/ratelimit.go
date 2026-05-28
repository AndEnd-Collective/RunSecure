package github

import (
	"net/http"
	"strconv"
)

type RateLimit struct {
	Limit     int
	Remaining int
	ResetUnix int64
}

func ParseRateLimit(h http.Header) RateLimit {
	r := RateLimit{}
	if v := h.Get("X-RateLimit-Limit"); v != "" {
		r.Limit, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		r.Remaining, _ = strconv.Atoi(v)
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		r.ResetUnix, _ = strconv.ParseInt(v, 10, 64)
	}
	return r
}
