.PHONY: all
all: image run-test

.PHONY: unit-test
unit-test:
	@echo "Running unit tests"
	@go test -v ./...

.PHONY: lint
lint:
	@echo "Running linter"
	@golangci-lint run

.PHONY: image
image:
	docker build -t localbuild/audito-maldito:latest .

.PHONY: run-test
run-test:
	docker run -ti \
		-e NODE_NAME=my-funky-node-name \
		-v $$PWD/journaldir:/var/log/journal/b3f9b6f421fc4af5b8770b54ebceb5ca:ro \
		-v $$PWD/machine-id:/etc/machine-id:ro \
		-v $$PWD/machine-id:/var/lib/dbus/machine-id:ro \
		-v $$PWD/os-release:/etc/os-release:ro \
		-v $$PWD/run:/var/run/audito-maldito \
		localbuild/audito-maldito:latest \
		--boot-id 050f00188b4b425592e35d0146cbf043 \
		--audit-log-path /var/run/audito-maldito/audit.log
