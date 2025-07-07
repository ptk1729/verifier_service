REPO_URL=https://github.com/ptk1729/go_proj
# REPO_URL=https://github.com/caddyserver/caddy
# REPO_URL=https://github.com/ptk1729/caddy_orig

run:
	go run main.go $(REPO_URL)

build:
	go build -o verifier main.go

# Individual check targets for testing
test-lint:
	go run main.go -lint $(REPO_URL)

test-vuln:
	go run main.go -vuln $(REPO_URL)

test-format:
	go run main.go -format $(REPO_URL)

test-env:
	go run main.go -env $(REPO_URL)

test-reviews:
	go run main.go -reviews $(REPO_URL)

test-custom:
	go run main.go -custom $(REPO_URL)

test-commit:
	go run main.go -commit -allowed-keys=73F56EE2CAD547655890B27149D9F27E562A5A49 $(REPO_URL)

# Full report with console output
test-full:
	go run main.go -print-report $(REPO_URL)
