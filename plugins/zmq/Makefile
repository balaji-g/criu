PLUGIN_NAME := zmq_plugin
PLUGIN_SOBJ := zmq_plugin.so

ARCH ?= x86

# Use CRIU include paths directly
PLUGIN_INCLUDE := -I../../criu/include
PLUGIN_INCLUDE += -I../../include
PLUGIN_INCLUDE += -I../../

PLUGIN_CFLAGS := -g -Wall -Wno-error -shared -nostartfiles -fPIC
PLUGIN_LDFLAGS := -ldl

all: $(PLUGIN_SOBJ)

zmq_plugin.so: zmq_plugin.c
	@echo "  CC       $@"
	@$(CC) $(PLUGIN_CFLAGS) $(PLUGIN_INCLUDE) $^ -o $@ $(PLUGIN_LDFLAGS)

clean:
	@$(RM) $(PLUGIN_SOBJ)
.PHONY: clean all
