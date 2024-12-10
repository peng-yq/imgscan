include $(CURDIR)/versions.mk

PREFIX := $(CURDIR)/bin
MODULE := imgscan

CMDS := $(patsubst ./cmd/%/,%,$(sort $(dir $(wildcard ./cmd/*/))))
CMD_TARGETS := $(patsubst %,bin-%, $(CMDS))

ifeq ($(VERSION),)
CLI_VERSION = $(LIB_VERSION)$(if $(LIB_TAG),-$(LIB_TAG))
else
CLI_VERSION = $(VERSION)
endif
CLI_VERSION_PACKAGE = imgscan/internal/info

GOOS ?= linux

all: cmd

ifneq ($(PREFIX),)
bin-%: COMMAND_BUILD_OPTIONS = -o $(PREFIX)/$(*)
endif

cmd: $(CMD_TARGETS)
$(CMD_TARGETS): bin-%:
	GOOS=$(GOOS) go build -ldflags "-extldflags=-Wl,-z,lazy -s -w -X $(CLI_VERSION_PACKAGE).gitCommit=$(GIT_COMMIT) -X $(CLI_VERSION_PACKAGE).version=$(CLI_VERSION)" $(COMMAND_BUILD_OPTIONS) $(MODULE)/cmd/$(*)

fmt:
	go fmt ./...

clean:
	rm -rf ./bin