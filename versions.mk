LIB_NAME := imgscan
LIB_VERSION := 0.1.0
LIB_TAG :=

# The package version is the combination of the library version and tag.
# If the tag is specified the two components are joined with a tilde (~).
PACKAGE_VERSION := $(LIB_VERSION)$(if $(LIB_TAG),~$(LIB_TAG))
PACKAGE_REVISION :=

GOLANG_VERSION := 1.22.9

GIT_COMMIT ?= $(shell git describe --match="" --dirty --long --always --abbrev=40 2> /dev/null || echo "")
GIT_COMMIT_SHORT ?= $(shell git rev-parse --short HEAD 2> /dev/null || echo "")
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2> /dev/null || echo "${GIT_COMMIT}")
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct  2> /dev/null || echo "")
