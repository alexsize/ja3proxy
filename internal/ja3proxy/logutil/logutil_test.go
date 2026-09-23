package logutil

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestSanitizedHandlerRedactsAttributesAndErrors(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(NewSanitizedHandler(slog.NewTextHandler(&output, nil))).With(
		slog.String("proxy_password", "password-canary"),
		slog.String("target", "https://user:password-canary@example.test:443"),
	)

	logger.Error("upstream failed", "error", errors.New("connect https://alice:another-canary@example.test:443: authorization Bearer bearer-canary"), "data", "raw-canary")

	got := output.String()
	for _, forbidden := range []string{"password-canary", "another-canary", "bearer-canary", "raw-canary"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("sanitized log contains secret %q: %s", forbidden, got)
		}
	}
	for _, expected := range []string{"proxy_password=[REDACTED]", "data=[REDACTED]", "REDACTED", "example.test"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("sanitized log missing %q: %s", expected, got)
		}
	}
}

func TestSanitizedHandlerRedactsNestedGroups(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(NewSanitizedHandler(slog.NewTextHandler(&output, nil)))
	logger.Info("nested", slog.Group("credentials", slog.String("token", "nested-canary"), slog.String("kind", "oauth")))

	got := output.String()
	if strings.Contains(got, "nested-canary") || !strings.Contains(got, "token=[REDACTED]") || !strings.Contains(got, "kind=oauth") {
		t.Fatalf("nested attributes were not sanitized: %s", got)
	}
}
