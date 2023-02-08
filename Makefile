GOFLAGS = -mod=vendor
export TAG := $(shell git rev-parse --short HEAD)
export PATH := $(PATH):/usr/local/go/bin
export COMPOSE_INTERACTIVE_NO_CLI := 1

input-filter-sets:
	CGO_ENABLED=0 go install $(GOFLAGS) -v ./cmd/fwtk-input-filter-sets

input-filter-bpf:
	go install $(GOFLAGS) -v ./cmd/fwtk-input-filter-bpf

test:
	go test $(GOFLAGS) -race -cover -coverprofile=coverage.out ./...

compat-self-test:
	python3 -m doctest -v tests/py/compare.py

compat-test: input-filter-sets input-filter-bpf compat-self-test
	bash tests/compat-sets.sh
	bash tests/compat-bpf.sh

bpf-integration-test: input-filter-bpf
	bash tests/integration-bpf.sh

docker-linter:
	docker build -f Dockerfile.linter -t firewall_toolkit-linter:$(TAG) .
	docker run -w /go/src/github.com/ngrok/firewall_toolkit firewall_toolkit-linter:$(TAG)

docker-build:
	docker build -t firewall_toolkit:$(TAG) .

docker-test: docker-build
	docker run firewall_toolkit:$(TAG) make test

docker-compat-test: docker-build
	docker run --cap-add NET_ADMIN firewall_toolkit:$(TAG) make compat-test

docker-integration-run: docker-build
	docker-compose -f tests/docker-compose.yml up -d fwtk-input-filter-sets-manager

docker-integration-stop:
	docker-compose -f tests/docker-compose.yml down

docker-integration-test: docker-integration-run
	bash tests/integration-sets.sh
	docker-compose -f tests/docker-compose.yml down

docker-ci: docker-linter docker-test docker-compat-test docker-integration-run docker-integration-test
