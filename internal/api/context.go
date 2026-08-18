package api

import (
	"context"
	"net/http"

	"github.com/maximalfocus/planless/internal/platform"
)

type ctxKey struct{}

func withCaller(r *http.Request, c platform.Caller) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, c)
}

func callerOf(r *http.Request) platform.Caller {
	c, _ := r.Context().Value(ctxKey{}).(platform.Caller)
	return c
}
