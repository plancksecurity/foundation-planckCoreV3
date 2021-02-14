include ../../DEPENDENCIES
export
PEP_MACHINE_DIR= $(PKG_INSTALL_PATH)/share/pEp
SEQUOIA_VERSION=${sequoia}
CURRENT_DISTRO=$(shell basename $(shell pwd))
IMAGE_NAME=${DOCKER_REGISTRY_HOST}/pep-$(CURRENT_DISTRO)-engine
DOCKERFILE=pEpEngine.$(CURRENT_DISTRO).Dockerfile
IS_TAGGED=${TAGGED_BUILD}
ifeq ($(IS_TAGGED), true)
# $CI_COMMIT_TAG is a predefined environment variable from Gitlab
	PEPENGINE_VERSION=${CI_COMMIT_TAG}
else
	PEPENGINE_VERSION=$(shell git rev-parse --short=8 HEAD)
endif
all:
	-docker pull $(IMAGE_NAME):latest
	cd ../../ && docker build --build-arg CURRENT_DISTRO=$(CURRENT_DISTRO) \
		      --build-arg DOCKER_REGISTRY_HOST=${DOCKER_REGISTRY_HOST} \
		      --build-arg PEPENGINE_VERSION=$(PEPENGINE_VERSION) \
		      --build-arg SEQUOIA_VERSION=$(SEQUOIA_VERSION) \
		      --build-arg PEP_MACHINE_DIR=$(PEP_MACHINE_DIR) \
		      --cache-from $(IMAGE_NAME):latest \
		      --tag=$(IMAGE_NAME):$(PEPENGINE_VERSION) \
		      --tag=$(IMAGE_NAME):latest \
		      -f scripts/${CURRENT_DISTRO}/$(DOCKERFILE) .
	docker push $(IMAGE_NAME):$(PEPENGINE_VERSION)
	docker push $(IMAGE_NAME):latest
