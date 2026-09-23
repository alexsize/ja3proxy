package logutil

import (
	"context"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

const componentKey = "component"

func WithComponent(component string, args ...any) *slog.Logger {
	return slog.With(componentArgs(component, args...)...)
}

func Debug(component string, msg string, args ...any) {
	slog.Debug(msg, componentArgs(component, args...)...)
}

func Info(component string, msg string, args ...any) {
	slog.Info(msg, componentArgs(component, args...)...)
}

func Warn(component string, msg string, args ...any) {
	slog.Warn(msg, componentArgs(component, args...)...)
}

func Error(component string, msg string, args ...any) {
	slog.Error(msg, componentArgs(component, args...)...)
}

func componentArgs(component string, args ...any) []any {
	componentArgs := make([]any, 0, len(args)+2)
	componentArgs = append(componentArgs, componentKey, component)
	return append(componentArgs, args...)
}

// NewSanitizedHandler wraps a slog handler and removes secrets before records
// reach the logging backend. It is intentionally placed at the handler
// boundary so attributes supplied through Logger.With are covered as well as
// attributes supplied by individual log calls.
func NewSanitizedHandler(next slog.Handler) slog.Handler {
	if next == nil {
		return nil
	}
	return sanitizedHandler{next: next}
}

type sanitizedHandler struct {
	next slog.Handler
}

func (h sanitizedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h sanitizedHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, sanitizeText(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		clean.AddAttrs(sanitizeAttr(attr))
		return true
	})
	return h.next.Handle(ctx, clean)
}

func (h sanitizedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		clean = append(clean, sanitizeAttr(attr))
	}
	return sanitizedHandler{next: h.next.WithAttrs(clean)}
}

func (h sanitizedHandler) WithGroup(name string) slog.Handler {
	return sanitizedHandler{next: h.next.WithGroup(name)}
}

const redactedValue = "[REDACTED]"

var sensitiveLogKey = regexp.MustCompile(`(?i)(^|[_-])(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|set-cookie|proxy[_-]?auth|raw|ticket|binder|identity|private[_-]?key|client[_-]?key|data|body)($|[_-])`)

func sanitizeAttr(attr slog.Attr) slog.Attr {
	if attr.Equal(slog.Attr{}) {
		return attr
	}
	key := attr.Key
	if sensitiveLogKey.MatchString(key) {
		return slog.String(key, redactedValue)
	}
	if strings.EqualFold(key, "error") || strings.HasSuffix(strings.ToLower(key), "_error") {
		return slog.String(key, sanitizeError(attr.Value))
	}
	return slog.Attr{Key: key, Value: sanitizeValue(attr.Value)}
}

func sanitizeValue(value slog.Value) slog.Value {
	if value.Kind() != slog.KindGroup {
		if value.Kind() == slog.KindString {
			return slog.StringValue(sanitizeText(value.String()))
		}
		return value
	}
	group := value.Group()
	clean := make([]slog.Attr, 0, len(group))
	for _, attr := range group {
		clean = append(clean, sanitizeAttr(attr))
	}
	return slog.GroupValue(clean...)
}

func sanitizeError(value slog.Value) string {
	if value.Kind() == slog.KindAny {
		if err, ok := value.Any().(error); ok && err != nil {
			return sanitizeText(err.Error())
		}
	}
	return sanitizeText(value.String())
}

func sanitizeText(text string) string {
	if text == "" {
		return text
	}
	// Remove credentials from URLs while retaining the useful destination.
	text = redactURLs(text)
	// Do not emit bearer/basic credentials even when they are embedded in an
	// error rather than supplied as a structured attribute.
	text = regexp.MustCompile(`(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`).ReplaceAllString(text, `$1 `+redactedValue)
	return text
}

func redactURLs(text string) string {
	return regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`).ReplaceAllStringFunc(text, func(match string) string {
		parsed, err := url.Parse(match)
		if err != nil || parsed.User == nil {
			return redactedValue + "@"
		}
		return parsed.Scheme + "://" + parsed.User.Username() + ":" + redactedValue + "@"
	})
}
