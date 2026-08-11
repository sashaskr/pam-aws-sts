# pam_aws_sts Makefile
# Build targets for the PAM module

CARGO := cargo
TARGET_LINUX_X86 := x86_64-unknown-linux-gnu
TARGET_LINUX_ARM := aarch64-unknown-linux-gnu
INSTALL_DIR := /lib/security
CONFIG_DIR := /etc

.PHONY: build build-linux build-linux-arm release test clean install integration-test docker-up docker-down

# Default: build for the host platform (development)
build:
	$(CARGO) build

# Release build for the host platform
release:
	$(CARGO) build --release

# Cross-compile for Linux x86_64 (primary deployment target)
build-linux:
	$(CARGO) build --release --target $(TARGET_LINUX_X86)

# Cross-compile for Linux ARM64
build-linux-arm:
	$(CARGO) build --release --target $(TARGET_LINUX_ARM)

# Run unit tests
test:
	$(CARGO) test

# Run clippy lints
lint:
	$(CARGO) clippy -- -D warnings

# Format code
fmt:
	$(CARGO) fmt

# Check formatting
fmt-check:
	$(CARGO) fmt -- --check

# Install the PAM module and configs (run as root on target Linux system)
install: release
	install -m 755 target/release/libpam_aws_sts.so $(INSTALL_DIR)/pam_aws_sts.so
	install -m 644 config/pam.d/awssts $(CONFIG_DIR)/pam.d/awssts
	@if [ ! -f $(CONFIG_DIR)/pam_aws_sts.toml ]; then \
		install -m 600 config/pam_aws_sts.toml $(CONFIG_DIR)/pam_aws_sts.toml; \
		echo "Installed default config to $(CONFIG_DIR)/pam_aws_sts.toml"; \
	else \
		echo "Config already exists at $(CONFIG_DIR)/pam_aws_sts.toml (not overwritten)"; \
	fi

# Install from cross-compiled Linux build
install-linux: build-linux
	install -m 755 target/$(TARGET_LINUX_X86)/release/libpam_aws_sts.so $(INSTALL_DIR)/pam_aws_sts.so
	install -m 644 config/pam.d/awssts $(CONFIG_DIR)/pam.d/awssts
	@if [ ! -f $(CONFIG_DIR)/pam_aws_sts.toml ]; then \
		install -m 600 config/pam_aws_sts.toml $(CONFIG_DIR)/pam_aws_sts.toml; \
	fi

# Start Docker containers for integration testing
docker-up:
	docker compose up -d --build
	docker compose exec postgres sh -c 'until pg_isready; do sleep 1; done'

# Stop Docker containers
docker-down:
	docker compose down -v

# Run integration tests (requires Docker)
integration-test: docker-up
	@echo "Integration test environment ready."
	@echo "Test with: PGPASSWORD='{\"AccessKeyId\":\"test\",\"SecretAccessKey\":\"test\",\"SessionToken\":\"test\"}' psql -h localhost -U pg_admin -d testdb"
	@echo ""
	@echo "For real AWS test:"
	@echo "  CREDS=\$$(aws_signing_helper credential-process ...)"
	@echo "  PGPASSWORD=\"\$$CREDS\" psql -h localhost -U pg_admin -d testdb"

# Clean build artifacts
clean:
	$(CARGO) clean
	docker compose down -v 2>/dev/null || true
