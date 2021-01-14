# If DRYCC_REGISTRY is not set, try to populate it from legacy DEV_REGISTRY
DRYCC_REGISTRY ?= $(DEV_REGISTRY)
IMAGE_PREFIX ?= drycc
COMPONENT ?= controller
SHORT_NAME ?= $(COMPONENT)
PLATFORM ?= linux/amd64,linux/arm64

include versioning.mk

SHELLCHECK_PREFIX := docker run -v ${CURDIR}:/workdir -w /workdir ${DRYCC_REGISTRY}drycc/go-dev shellcheck
SHELL_SCRIPTS = $(wildcard rootfs/bin/*) $(shell find "rootfs" -name '*.sh') $(wildcard _scripts/*.sh)

# Test processes used in quick unit testing
TEST_PROCS ?= 4

check-kubectl:
	@if [ -z $$(which kubectl) ]; then \
	  echo "kubectl binary could not be located"; \
	  exit 2; \
	fi

check-docker:
	@if [ -z $$(which docker) ]; then \
	  echo "Missing \`docker\` client which is required for development"; \
	  exit 2; \
	fi

build: docker-build

docker-build: check-docker
	docker build ${DOCKER_BUILD_FLAGS} -t ${IMAGE} rootfs
	docker tag ${IMAGE} ${MUTABLE_IMAGE}

docker-buildx: check-docker
	docker buildx build --platform ${PLATFORM} -t ${IMAGE} rootfs --push

docker-build-test: check-docker
	docker build ${DOCKER_BUILD_FLAGS} -t ${IMAGE}.test -f rootfs/Dockerfile.test rootfs

deploy: check-kubectl docker-build docker-push
	kubectl --namespace=drycc patch deployment drycc-$(COMPONENT) --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"$(IMAGE)"}]'

clean: check-docker
	docker rmi $(IMAGE)

commit-hook:
	cp _scripts/util/commit-msg .git/hooks/commit-msg

full-clean: check-docker
	docker images -q $(IMAGE_PREFIX)/$(COMPONENT) | xargs docker rmi -f

test: test-style test-unit test-functional

test-style: docker-build-test
	docker run -v ${CURDIR}:/test -w /test/rootfs ${IMAGE}.test /test/rootfs/bin/test-style
	${SHELLCHECK_PREFIX} $(SHELL_SCRIPTS)

test-unit: docker-build-test
	docker run -v ${CURDIR}:/test -w /test/rootfs ${IMAGE}.test /test/rootfs/bin/test-unit

test-functional:
	@echo "Implement functional tests in _tests directory"

test-integration:
	@echo "Check https://github.com/drycc/workflow-e2e for the complete integration test suite"

upload-coverage:
	$(eval CI_ENV := $(shell curl -s https://codecov.io/env | bash))
	docker run ${CI_ENV} -v ${CURDIR}:/test -w /test/rootfs ${IMAGE}.test codecov --required

.PHONY: check-kubectl check-docker build docker-build docker-build-test deploy clean commit-hook full-clean test test-style test-unit test-functional test-integration upload-coverage
