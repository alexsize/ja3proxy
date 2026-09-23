package ja3proxy

import (
	"log/slog"
	"os"

	cflog "github.com/cloudflare/cfssl/log"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
)

func init() {
	cflog.Level = cflog.LevelWarning
	configureDefaultLogger(slog.LevelInfo)
}

func configureDefaultLogger(level slog.Level) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(logutil.NewSanitizedHandler(handler)))
}
