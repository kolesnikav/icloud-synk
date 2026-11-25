package icloud

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSubmit2FAAcceptsValidConflictForTrustedDeviceAndSMS(t *testing.T) {
	tests := []struct {
		name string
		ch   *Challenge
		path string
	}{
		{name: "trusted device", ch: &Challenge{}, path: "/appleauth/auth/verify/trusteddevice/securitycode"},
		{name: "SMS", ch: &Challenge{smsID: 2}, path: "/appleauth/auth/verify/phone/securitycode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			cl := &Client{
				http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					if req.URL.Path != tt.path {
						t.Errorf("request path = %q, want %q", req.URL.Path, tt.path)
					}
					return &http.Response{
						StatusCode: http.StatusConflict,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(`{"success":0,"securityCode":{"valid":true}}`)),
						Request:    req,
					}, nil
				})},
				jar: NewJar(), sess: &Session{Webservices: map[string]string{}},
			}

			if err := cl.submit2FA(context.Background(), "531294", tt.ch); err != nil {
				t.Fatalf("submit2FA returned error for valid code: %v", err)
			}
			if !called {
				t.Fatal("submit2FA did not send a request")
			}
		})
	}
}

func TestSubmit2FARejectsConflictWithoutValidCode(t *testing.T) {
	for _, body := range []string{
		`{"success":0,"securityCode":{"valid":false}}`,
		`{"success":0,"securityCode":{}}`,
		`not-json`,
	} {
		t.Run(body, func(t *testing.T) {
			cl := &Client{
				http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusConflict,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(body)),
						Request:    req,
					}, nil
				})},
				jar: NewJar(), sess: &Session{Webservices: map[string]string{}},
			}
			if err := cl.submit2FA(context.Background(), "531294", &Challenge{}); err == nil {
				t.Fatalf("submit2FA accepted HTTP 409 body %q", body)
			}
		})
	}
}
