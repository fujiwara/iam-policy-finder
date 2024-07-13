.PHONY: clean test

iam-policy-finder: go.* *.go
	go build -o $@ cmd/iam-policy-finder/main.go

clean:
	rm -rf iam-policy-finder dist/

test:
	go test -v ./...

install:
	go install github.com/fujiwara/iam-policy-finder/cmd/iam-policy-finder

dist:
	goreleaser build --snapshot --clean
