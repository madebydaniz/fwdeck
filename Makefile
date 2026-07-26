# FWDeck — developer & contributor tasks. Run `make` for the menu.
#
# The dev container carries a real firewalld; targets that touch the firewall
# run inside it. Pure Rust checks (fmt/clippy/test) run on your host when you
# have the toolchain — otherwise `make shell` and run them in the container.

COMPOSE ?= docker compose
CARGO   ?= cargo
SERVICE ?= dev

.DEFAULT_GOAL := help

##@ Run & develop

.PHONY: run
run: ## Launch the TUI in the dev container (real firewalld). DNS flaky? use run-offline
	$(COMPOSE) run --rm $(SERVICE) $(CARGO) run

.PHONY: run-offline
run-offline: ## Same as run, built offline from your host's cargo cache (skips container DNS)
	$(COMPOSE) run --rm -v "$$HOME/.cargo/registry:/root/.cargo/registry" $(SERVICE) $(CARGO) run --offline

.PHONY: shell
shell: ## Open a shell in the dev container
	$(COMPOSE) run --rm $(SERVICE) bash

##@ Test & lint

.PHONY: test
test: ## Run the unit test suite (never touches a firewall)
	$(CARGO) test --locked

.PHONY: test-real
test-real: ## Run the real-firewalld integration tests (dev container, serial)
	$(COMPOSE) run --rm $(SERVICE) $(CARGO) test --features dbus --test real_firewalld -- --ignored --test-threads=1

.PHONY: fmt
fmt: ## Format the whole workspace
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without writing (CI gate)
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint: ## Clippy with warnings denied (default features)
	$(CARGO) clippy --all-targets --locked -- -D warnings

.PHONY: check
check: fmt-check lint test ## Run the host-runnable CI gates: fmt, clippy, tests

.PHONY: msrv
msrv: ## Check it still builds on the MSRV (needs `rustup toolchain add 1.88`)
	$(CARGO) +1.88 check --all-targets --locked

.PHONY: deny
deny: ## Audit licenses & advisories (needs cargo-deny)
	$(CARGO) deny check advisories licenses bans sources

##@ Build & install

.PHONY: build
build: ## Build an optimized release binary
	$(CARGO) build --release --locked

.PHONY: install
install: ## Install fwdeck from this checkout
	$(CARGO) install --path . --locked

##@ Docs & site

.PHONY: site
site: ## Assemble and open the website locally
	./scripts/preview-site.sh

.PHONY: doc
doc: ## Build and open the API docs
	$(CARGO) doc --no-deps --open

##@ Housekeeping

.PHONY: clean
clean: ## Remove Rust build artifacts
	$(CARGO) clean

.PHONY: help
help: ## Show this help
	@printf '\033[1;38;2;189;147;249m%s\033[0m\n' '███████╗██╗    ██╗██████╗ ███████╗ ██████╗██╗  ██╗'
	@printf '\033[1;38;2;215;137;229m%s\033[0m\n' '██╔════╝██║    ██║██╔══██╗██╔════╝██╔════╝██║ ██╔╝'
	@printf '\033[1;38;2;242;126;208m%s\033[0m\n' '█████╗  ██║ █╗ ██║██║  ██║█████╗  ██║     █████╔╝ '
	@printf '\033[1;38;2;232;143;209m%s\033[0m\n' '██╔══╝  ██║███╗██║██║  ██║██╔══╝  ██║     ██╔═██╗ '
	@printf '\033[1;38;2;185;188;231m%s\033[0m\n' '██║     ╚███╔███╔╝██████╔╝███████╗╚██████╗██║  ██╗'
	@printf '\033[1;38;2;139;233;253m%s\033[0m\n' '╚═╝      ╚══╝╚══╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝'
	@printf '  \033[2mA safety-first terminal UI for firewalld\033[0m\n\n'
	@printf 'Usage:\n  make \033[36m<target>\033[0m\n'
	@awk 'BEGIN {FS = ":.*## "} /^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next} /^[a-zA-Z0-9_%-]+:.*## / {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\n'
