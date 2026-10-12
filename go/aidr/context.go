package aidr

import "context"

type contextKey struct{}

// ContextKey is the key under which Middleware stores the verified [Result].
var ContextKey = contextKey{}

func withResult(parent context.Context, result Result) context.Context {
	return context.WithValue(parent, ContextKey, result)
}

// FromContext returns the verified agent identity attached by Middleware.
//
// The boolean is not decoration: with `optional` middleware an unidentified request reaches the
// handler with nothing attached, and a handler that ignores the boolean would read a zero-valued
// Result as an agent with empty capabilities rather than as no agent at all.
func FromContext(ctx context.Context) (Result, bool) {
	result, ok := ctx.Value(ContextKey).(Result)
	return result, ok
}
