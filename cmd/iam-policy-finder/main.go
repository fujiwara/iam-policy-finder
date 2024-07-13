package main

import (
	"context"
	"log"

	finder "github.com/fujiwara/iam-policy-finder"
)

func main() {
	ctx := context.TODO()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	return finder.Run(ctx)
}
