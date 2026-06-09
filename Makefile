# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -Iinclude -D_GNU_SOURCE
LDFLAGS = -lcurl -ljson-c -lpthread -lssl -lcrypto

# Directories
SRC_DIR = src
CORE_DIR = $(SRC_DIR)/core
UTILS_DIR = $(SRC_DIR)/utils
INC_DIR = include
BUILD_DIR = build
BIN_DIR = .

# Target executable
TARGET = $(BIN_DIR)/mcp-inject

# Source files
SOURCES = $(SRC_DIR)/main.c \
          $(CORE_DIR)/scanner.c \
          $(CORE_DIR)/transport.c \
          $(CORE_DIR)/payload.c \
          $(CORE_DIR)/detect.c \
          $(CORE_DIR)/exploit.c \
          $(CORE_DIR)/report.c \
          $(CORE_DIR)/evasion.c \
          $(UTILS_DIR)/crypto.c \
          $(UTILS_DIR)/logger.c

# Object files (maps src/xyz.c to build/xyz.o)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Default target
all: $(TARGET)

# Link object files into final executable
$(TARGET): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo ""
	@echo "[+] Build successful: $(TARGET)"
	@echo "[-] Run with: ./mcp-inject -t http://target.com"

# Compile C files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	@echo "[-] Clean complete"

# Build and run with default target
run: $(TARGET)
	./$(TARGET) -t http://localhost:8080 -v

# Quick test with safe target
test: $(TARGET)
	@echo "[*] Running quick test against httpbin.org..."
	./$(TARGET) -t https://httpbin.org/post --timeout 5 -v

# Install to /usr/local/bin
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "[+] Installed to /usr/local/bin/mcp-inject"

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/mcp-inject
	@echo "[-] Uninstalled"

# Show help
help:
	@echo "MCP Injection Scanner - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make          - Build the scanner"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make run      - Build and run with default target"
	@echo "  make test     - Quick test against httpbin.org"
	@echo "  make install  - Install to /usr/local/bin"
	@echo "  make uninstall- Remove installed files"
	@echo "  make help     - Show this help"
	@echo ""
	@echo "Example usage after build:"
	@echo "  ./mcp-inject -t http://localhost:8080"
	@echo "  ./mcp-inject -t http://target.com -v -e -E"
	@echo "  ./mcp-inject -t http://target.com -T 16 -o report.json"

# Phony targets
.PHONY: all clean run test install uninstall help