package main

import (
	"context"
	"log/slog"
	"os"

	finder "github.com/fujiwara/iam-policy-finder"
)

func main() {
	ctx := context.TODO()
	if err := run(ctx); err != nil {
		slog.Error("failed to run", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	return finder.Run(ctx)
}
