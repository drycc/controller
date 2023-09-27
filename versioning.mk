MUTABLE_VERSION ?= canary
VERSION ?= git-$(shell git rev-parse --short HEAD)

IMAGE := ${DRYCC_REGISTRY}/${IMAGE_PREFIX}/${SHORT_NAME}:${VERSION}
MUTABLE_IMAGE := ${DRYCC_REGISTRY}/${IMAGE_PREFIX}/${SHORT_NAME}:${MUTABLE_VERSION}

info:
	@echo "Build tag:       ${VERSION}"
	@echo "Registry:        ${DRYCC_REGISTRY}"
	@echo "Immutable tag:   ${IMAGE}"
	@echo "Mutable tag:     ${MUTABLE_IMAGE}"

.PHONY: podman-push
podman-push: podman-mutable-push podman-immutable-push

.PHONY: podman-immutable-push
podman-immutable-push:
	podman push ${IMAGE}

.PHONY: podman-mutable-push
podman-mutable-push:
	podman push ${MUTABLE_IMAGE}
