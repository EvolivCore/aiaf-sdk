package aidr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The Host-header replay (found 2026-10-10; origin.go): a request is judged as THIS site, never as
// the Host the client sent, except on localhost.

func requestFor(t *testing.T, testCase vectorCase, target, host string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(testCase.Method, target, nil)
	request.Host = host
	request.Header.Set("X-Forwarded-Proto", "https")
	for name, value := range testCase.Headers {
		if strings.EqualFold(name, "host") {
			continue
		}
		request.Header.Set(name, value)
	}
	return request
}

func caseNamedGo(suite vectorSuite, name string) vectorCase {
	for _, c := range suite.Cases {
		if c.Name == name {
			return c
		}
	}
	return vectorCase{}
}

func TestRequestSignedForAnotherHostIsRefusedEvenWithThatHost(t *testing.T) {
	t.Setenv(PublicOriginEnv, "")
	suite := loadVectors(t).Suites[0]
	shop := []string{"https://shop.example"}
	// What VerifyRequest does — resolve this site's origin from the Host, then verify — at the
	// vectors' pinned instant (VerifyRequest itself uses the wall clock).
	judge := func(testCase vectorCase, host string) error {
		origin, err := resolveOrigin(shop, "https", host)
		if err != nil {
			return err
		}
		verifier := NewVerifier(trustFor(t, suite, suite.Revocation.DeltaBefore),
			Policy{ExpectedIssuer: suite.Issuer, PublicOrigins: shop}, NewNonceCache(0, 0))
		_, err = verifier.Verify(testCase.Method, origin+"/api/products", testCase.Headers, evaluateAt)
		return err
	}
	// Signed for other.example, sent here claiming Host: other.example: judged as shop.example.
	if err := judge(caseNamedGo(suite, "replay from another host is refused"), "other.example"); err == nil {
		t.Fatal("a request signed for another host was accepted")
	}
	// Control: this site's own agent passes whatever Host a proxy forwards.
	if err := judge(firstAllowCase(suite), "internal:8080"); err != nil {
		t.Fatalf("this site's agent was refused: %v", err)
	}
}

func TestOriginResolution(t *testing.T) {
	t.Setenv(PublicOriginEnv, "")
	several := []string{"https://shop.example", "https://www.shop.example"}
	if got, _ := resolveOrigin(several, "https", "www.shop.example"); got != "https://www.shop.example" {
		t.Errorf("matching host: got %q", got)
	}
	if got, _ := resolveOrigin(several, "https", "other.example"); got != "https://shop.example" {
		t.Errorf("other host: got %q, want the first origin", got)
	}
	for _, host := range []string{"localhost:3000", "127.0.0.1:8080", "[::1]:3000", "app.localhost"} {
		if !IsLoopbackHost(host) {
			t.Errorf("%s is loopback", host)
		}
	}
	for _, host := range []string{"127.evil.example", "localhost.evil.example"} {
		if IsLoopbackHost(host) {
			t.Errorf("%s is not loopback", host)
		}
	}
	t.Setenv(PublicOriginEnv, "https://a.example,https://b.example")
	if got, _ := resolveOrigin(nil, "https", "b.example"); got != "https://b.example" {
		t.Errorf("from the environment: got %q", got)
	}
}

func TestWithoutAnOriginAgentsElsewhereAreRefusedFrom020(t *testing.T) {
	t.Setenv(PublicOriginEnv, "")
	EnforcePublicOrigin = true
	defer func() { EnforcePublicOrigin = false }()
	if _, err := resolveOrigin(nil, "https", "shop.example"); Code(err) != CodePublicOriginRequired {
		t.Fatalf("code = %q, want %q", Code(err), CodePublicOriginRequired)
	}
	if _, err := resolveOrigin(nil, "https", "localhost:3000"); err != nil {
		t.Fatalf("localhost must not need an origin: %v", err)
	}

	suite := loadVectors(t).Suites[0]
	verifier := NewVerifier(trustFor(t, suite, suite.Revocation.DeltaBefore),
		Policy{ExpectedIssuer: suite.Issuer}, NewNonceCache(0, 0))
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), true)

	agent := httptest.NewRecorder()
	handler.ServeHTTP(agent, requestFor(t, firstAllowCase(suite), "/api/products", "shop.example"))
	if agent.Code != http.StatusServiceUnavailable {
		t.Errorf("agent: status %d, want 503", agent.Code)
	}
	person := httptest.NewRecorder()
	handler.ServeHTTP(person, requestFor(t, vectorCase{Method: "GET"}, "/api/products", "shop.example"))
	if person.Code != http.StatusOK {
		t.Errorf("person: status %d, want 200 (people are never refused for the site's configuration)", person.Code)
	}
}
