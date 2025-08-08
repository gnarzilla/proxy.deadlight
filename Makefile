# Deadlight Proxy v4.0 - Makefile
# Build system for the modular proxy server

# Project information
PROJECT = deadlight
VERSION = 4.0.0
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib
CONFDIR = /etc/deadlight
LOGDIR = /var/log/deadlight
CACHEDIR = /var/cache/deadlight

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2 -g
LDFLAGS = -Wl,--as-needed
LIBS = -lssl -lcrypto -lpthread

# Package config for GLib/GIO
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0 gio-2.0 gio-unix-2.0 json-glib-1.0)

# All flags combined
ALL_CFLAGS = $(CFLAGS) $(GLIB_CFLAGS) -DDEADLIGHT_VERSION=\"$(VERSION)\" -Isrc
ALL_LIBS = $(LIBS) $(GLIB_LIBS)

# Directories
SRCDIR = src/core
PLUGINDIR = src/plugins
TESTDIR = src/tests
OBJDIR = obj
BINDIR = bin

# Source files
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

# Protocol sources
PROTOCOL_SOURCES = src/protocols/http.c \
                   src/protocols/imap.c \
				   src/protocols/imaps.c \
				   src/protocols/socks.c \
				   src/protocols/smtp.c \
				   src/protocols/api.c

# Object files
CORE_OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(CORE_SOURCES))
PROTOCOL_OBJECTS = $(patsubst src/protocols/%.c,$(OBJDIR)/%.o,$(PROTOCOL_SOURCES))
ALL_OBJECTS = $(CORE_OBJECTS) $(PROTOCOL_OBJECTS)

# Targets
MAIN_TARGET = $(BINDIR)/$(PROJECT)

# Default target
all: dirs $(MAIN_TARGET)

# Create directories
dirs:
	@mkdir -p $(OBJDIR) $(BINDIR) $(PLUGINDIR) $(TESTDIR)

# Main executable
$(MAIN_TARGET): $(ALL_OBJECTS)
	@echo "🔗 Linking $(PROJECT)..."
	@$(CC) $(LDFLAGS) -o $@ $^ $(ALL_LIBS)
	@echo "✅ Built $(PROJECT)"

# Object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/deadlight.h
	@echo "🔨 Compiling $<..."
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: src/protocols/%.c src/core/deadlight.h
	@echo "🔨 Compiling $<..."
	@$(CC) $(ALL_CFLAGS) -c $< -o $@

# Clean
clean:
	@echo "🧹 Cleaning build files..."
	@rm -rf $(OBJDIR) $(BINDIR)
	@echo "✅ Clean complete"

# Run
run: $(MAIN_TARGET)
	./$(MAIN_TARGET) -v

# Development build
dev: CFLAGS += -DDEBUG -g3 -O0
dev: clean all
	@echo "🚀 Starting development server..."
	./$(MAIN_TARGET) -v

.PHONY: all dirs clean run dev
