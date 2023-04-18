GOLANGCI_LINT_VERSION = v1.52.2

TOOLS_DIR = .tools

LIVE_INSTANCE?=""
INSTANCE_USER?=core
LIVE_INSTANCE_BOOT_ID=
TEST_LIVE_INSTANCE_DIR=live-instance-test

IMAGE=ghcr.io/metal-toolbox/audito-maldito
TAG=latest

.PHONY: all
all: image run-test

.PHONY: unit-test
unit-test:
	@echo "Running unit tests"
	@go test -v ./...

.PHONY: integration-test
integration-test:
	@echo "Running integration tests"
	@go test -tags int -v ./internal/integration_tests/...

.PHONY: coverage
coverage:
	@echo Generating coverage report...
	# The "-coverpkg ./..." tells go to calculate coverage for
	# packages that are indirectly tested by other packages.
	# This is required for integration test code coverage.
	@go test -timeout 10m -coverpkg ./... ./... -coverprofile=coverage.out -covermode=atomic
	@go tool cover -func=coverage.out
	@go tool cover -html=coverage.out

.PHONY: lint
lint: $(TOOLS_DIR)/golangci-lint
	@echo Linting Go files...
	@$(TOOLS_DIR)/golangci-lint run

.PHONY: image
image:
	docker build -t $(IMAGE):$(TAG) .

.PHONY: verify-live-instance-var
verify-live-instance-var:
ifeq ($(LIVE_INSTANCE),)
	$(error LIVE_INSTANCE is not set)
else
	@echo "LIVE_INSTANCE is set to $(LIVE_INSTANCE)"
endif

$(TEST_LIVE_INSTANCE_DIR):
	@mkdir -p $(TEST_LIVE_INSTANCE_DIR)

$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE): $(TEST_LIVE_INSTANCE_DIR)
	@echo "Downloading $(LIVE_INSTANCE) to $(TEST_LIVE_INSTANCE_DIR)"
	@mkdir -p $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)
	$(eval LIVE_INSTANCE_BOOT_ID := $(shell ssh $(INSTANCE_USER)@$(LIVE_INSTANCE) "sudo cat /proc/sys/kernel/random/boot_id" | sed 's/-//g'))
	@echo "Using Boot ID $(LIVE_INSTANCE_BOOT_ID)"
	echo $(LIVE_INSTANCE_BOOT_ID) > $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/boot_id
	scp -r $(INSTANCE_USER)@$(LIVE_INSTANCE):/var/log/journal $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)
	@echo "Downloading Machine-ID"
	scp $(INSTANCE_USER)@$(LIVE_INSTANCE):/etc/machine-id $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/machine-id
	@echo "Downloading os-release"
	scp $(INSTANCE_USER)@$(LIVE_INSTANCE):/etc/os-release $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/os-release

$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run:
	@echo "Ensuring run dir"
	mkdir -p $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run

.PHONY: instance-test-audit-log
instance-test-audit-log:
	@echo "Ensuring audit log in run dir"
	touch $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run/audit.log
	@echo "truncating audit log"
	echo "" > $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run/audit.log

.PHONY: run-test
instance-test: verify-live-instance-var $(TEST_LIVE_INSTANCE_DIR) $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE) $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run instance-test-audit-log image
	docker run -ti \
		-e NODE_NAME=my-funky-node-name \
		-v $$PWD/$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/journal:/var/log/journal:ro \
		-v $$PWD/$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/machine-id:/etc/machine-id:ro \
		-v $$PWD/$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/os-release:/etc/os-release:ro \
		-v $$PWD/$(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/run:/var/run/audito-maldito \
		$(IMAGE):$(TAG) \
		--boot-id $(shell cat $(TEST_LIVE_INSTANCE_DIR)/$(LIVE_INSTANCE)/boot_id) \
		--audit-log-path /var/run/audito-maldito/audit.log

.PHONY: clean-instance-test
clean-instance-test:
	@rm -rf $(TEST_LIVE_INSTANCE_DIR)

$(TOOLS_DIR):
	mkdir -p $(TOOLS_DIR)

$(TOOLS_DIR)/golangci-lint:
	export \
		VERSION=$(GOLANGCI_LINT_VERSION) \
		URL=https://raw.githubusercontent.com/golangci/golangci-lint \
		BINDIR=$(TOOLS_DIR) && \
	curl -sfL $$URL/$$VERSION/install.sh | sh -s $$VERSION
	$(TOOLS_DIR)/golangci-lint version
	$(TOOLS_DIR)/golangci-lint linters
