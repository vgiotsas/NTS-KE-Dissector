BINARY := ntsclient
SRCS := client.go version.go go.mod go.sum

$(BINARY): $(SRCS)
	go build -o $@

lint:
# see: .golangci.yml
	-golangci-lint run
	-golangci-lint run bump-version.go

bump-major:
	go run bump-version.go version.go major
bump-minor:
	go run bump-version.go version.go minor
bump-patch:
	go run bump-version.go version.go patch
