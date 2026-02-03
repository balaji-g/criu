PLUGIN_NAME := zmq_plugin
PLUGIN_SOBJ := zmq_plugin.so
ZMQ_CHECKPOINT_BIN := zmq-checkpoint

ARCH ?= x86

# Use CRIU include paths directly
PLUGIN_INCLUDE := -I../../criu/include
PLUGIN_INCLUDE += -I../../include
PLUGIN_INCLUDE += -I../../

PLUGIN_CFLAGS := -g -Wall -Wno-error -shared -nostartfiles -fPIC
PLUGIN_LDFLAGS := -ldl

TOOL_CFLAGS := -g -Wall -Wno-error
TOOL_LDFLAGS := -ldl

all: $(PLUGIN_SOBJ) $(ZMQ_CHECKPOINT_BIN)

zmq_plugin.so: zmq_plugin.c
	@echo "  CC       $@"
	@$(CC) $(PLUGIN_CFLAGS) $(PLUGIN_INCLUDE) $^ -o $@ $(PLUGIN_LDFLAGS)

zmq-checkpoint: zmq-checkpoint.c
	@echo "  CC       $@"
	@$(CC) $(TOOL_CFLAGS) $^ -o $@ $(TOOL_LDFLAGS)

clean:
	@$(RM) $(PLUGIN_SOBJ) $(ZMQ_CHECKPOINT_BIN)
.PHONY: clean all
