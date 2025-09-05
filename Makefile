# Deadlight Proxy v4.0 - Makefile
# Build system for the modular proxy server

#=============================================================================
# Project Configuration
#=============================================================================
PROJECT = deadlight
VERSION = 5.0.0
PREFIX = /usr/local

#=============================================================================
# Compiler Configuration
#=============================================================================
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2 -g
LDFLAGS = -Wl,--as-needed
LIBS = -lssl -lcrypto -lpthread

# Package config for GLib/GIO
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0 gmodule-2.0)

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc
ALL_LIBS = $(LIBS) $(GLIB_LIBS)

#=============================================================================
# Directory Structure
#=============================================================================
SRCDIR = src/core
PLUGINDIR = src/plugins
TESTDIR = src/tests
OBJDIR = obj
BINDIR = bin
PLUGIN_BINDIR = $(BINDIR)/plugins

# Installation directories
LIBDIR = $(PREFIX)/lib
CONFDIR = /etc/deadlight
LOGDIR = /var/log/deadlight
CACHEDIR = /var/cache/deadlight

#=============================================================================
# Source Files
#=============================================================================
CORE_SOURCES = $(SRCDIR)/main.c \
               $(SRCDIR)/config.c \
               $(SRCDIR)/context.c \
               $(SRCDIR)/logging.c \
               $(SRCDIR)/network.c \
               $(SRCDIR)/ssl.c \
               $(SRCDIR)/protocols.c \
               $(SRCDIR)/plugins.c \
               $(SRCDIR)/request.c \
               $(SRCDIR)/utils.c \
               $(SRCDIR)/ssl_tunnel.c \
               $(SRCDIR)/connection_pool.c

PROTOCOL_SOURCES = src/protocols/http.c \
                   src/protocols/imap.c \
                   src/protocols/imaps.c \
                   src/protocols/socks.c \
                   src/protocols/smtp.c \
                   src/protocols/api.c

PLUGIN_SOURCES = $(PLUGINDIR)/adblocker.c \
                 $(PLUGINDIR)/ratelimiter.c

#=============================================================================
# Object Files
#=============================================================================
CORE_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(CORE_SOURCES))
PROTOCOL_OBJECTS = $(patsubst src/protocols/%.c,$(OBJDIR)/%.o,$(PROTOCOL_SOURCES))
ALL_OBJECTS = $(CORE_OBJECTS) $(PROTOCOL_OBJECTS)

#=============================================================================
# Targets
#=============================================================================
MAIN_TARGET = $(BINDIR)/$(PROJECT)
PLUGIN_TARGETS = $(PLUGIN_BINDIR)/adblocker.so \
                 $(PLUGIN_BINDIR)/ratelimiter.so

#=============================================================================
# Build Rules
#=============================================================================

# Default target
all: dirs $(MAIN_TARGET) plugins

# Create necessary directories
dirs:
	@mkdir -p $(OBJDIR) $(BINDIR) $(PLUGIN_BINDIR)

# Main executable
$(MAIN_TARGET): $(ALL_OBJECTS)
	@echo "🔗 Linking $(PROJECT)..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(ALL_LIBS)
	@echo "✅ Built $(PROJECT) v$(VERSION)"

# Core object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/deadlight.h
	@echo "🔨 Compiling $<..."
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

# Protocol object files
$(OBJDIR)/%.o: src/protocols/%.c src/core/deadlight.h
	@echo "🔨 Compiling $<..."
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

# Plugin builds
plugins: $(PLUGIN_TARGETS)

$(PLUGIN_BINDIR)/adblocker.so: $(PLUGINDIR)/adblocker.c $(PLUGINDIR)/adblocker.h | $(PLUGIN_BINDIR)
	@echo "🔌 Building AdBlocker plugin..."
	@$(CC) $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc -Isrc/core -fPIC -shared -o $@ $< $(ALL_LIBS)

$(PLUGIN_BINDIR)/ratelimiter.so: $(PLUGINDIR)/ratelimiter.c $(PLUGINDIR)/ratelimiter.h | $(PLUGIN_BINDIR)
	@echo "🔌 Building RateLimiter plugin..."
	@$(CC) $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc -Isrc/core -fPIC -shared -o $@ $< $(ALL_LIBS)

#=============================================================================
# Utility Targets
#=============================================================================

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build files..."
	@rm -rf $(OBJDIR) $(BINDIR)
	@echo "✅ Clean complete"

# Run the built executable
run: $(MAIN_TARGET)
	@echo "🚀 Running $(PROJECT)..."
	@./$(MAIN_TARGET) -v

# Development build with debug symbols
dev: CFLAGS += -DDEBUG -g3 -O0
dev: clean all
	@echo "🚀 Starting development server..."
	@./$(MAIN_TARGET) -v

# Build only plugins
plugins-only: dirs $(PLUGIN_TARGETS)
	@echo "✅ Plugins built"

# Install target (basic structure)
install: all
	@echo "📦 Installing $(PROJECT)..."
	@install -d $(DESTDIR)$(PREFIX)/bin
	@install -d $(DESTDIR)$(LIBDIR)/$(PROJECT)/plugins
	@install -d $(DESTDIR)$(CONFDIR)
	@install -d $(DESTDIR)$(LOGDIR)
	@install -d $(DESTDIR)$(CACHEDIR)
	@install -m 755 $(MAIN_TARGET) $(DESTDIR)$(PREFIX)/bin/
	@install -m 644 $(PLUGIN_TARGETS) $(DESTDIR)$(LIBDIR)/$(PROJECT)/plugins/
	@echo "✅ Installation complete"

# Uninstall target
uninstall:
	@echo "🗑️  Uninstalling $(PROJECT)..."
	@rm -f $(DESTDIR)$(PREFIX)/bin/$(PROJECT)
	@rm -rf $(DESTDIR)$(LIBDIR)/$(PROJECT)
	@echo "✅ Uninstall complete"

# Help target
help:
	@echo "Deadlight Proxy v$(VERSION) - Available targets:"
	@echo "  all          - Build everything (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run the proxy"
	@echo "  dev          - Build with debug flags and run"
	@echo "  plugins      - Build all plugins"
	@echo "  plugins-only - Build only plugins (no main executable)"
	@echo "  install      - Install to system directories"
	@echo "  uninstall    - Remove from system directories"
	@echo "  help         - Show this help message"

#=============================================================================
# Special Targets
#=============================================================================
.PHONY: all dirs clean run dev plugins plugins-only install uninstall help debug-plugin check-deps