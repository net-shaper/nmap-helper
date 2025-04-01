# Masscan Helper Makefile

# Configuration variables
PACKAGE_NAME = nmap-helper
BIN_NAME = nmap-helper
INSTALL_DIR = $(HOME)/.local/bin
# Alternative system-wide install location (requires sudo)
# INSTALL_DIR = /usr/local/bin

# Colors for pretty output
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
RED = "\033[0;31m"
NC = "\033[0m" # No Color

.PHONY: all build release debug install uninstall clean help

# Default target
all: release

# Build debug version
debug:
	@cargo build

# Build release version
release:
	@cargo build --release

# Install release version
install: release
	@mkdir -p $(INSTALL_DIR)
	@cp target/release/$(BIN_NAME) $(INSTALL_DIR)/
	@echo "Make sure $(INSTALL_DIR) is in your PATH."
	@echo "Try running: $(BIN_NAME) --help"

# Uninstall
uninstall:
	@rm -f $(INSTALL_DIR)/$(BIN_NAME)

# Clean build artifacts
clean:
	@cargo clean

