include ../../DEPENDENCIES
export
PEP_MACHINE_DIR= $(PKG_INSTALL_PATH)/share/pEp
YML2_VERSION=${yml2}
SEQUOIA_VERSION=$(shell echo ${sequoia} | sed 's/\//-/')
CURRENT_DISTRO=$(shell basename $(shell pwd))
IMAGE_NAME=${DOCKER_REGISTRY_HOST}/pep-$(CURRENT_DISTRO)-engine
DOCKERFILE=pEpEngine.$(CURRENT_DISTRO).Dockerfile
PKG_BUILD_IMAGE=${DOCKER_REGISTRY_HOST}/fpm-$(CURRENT_DISTRO)
PKG_INSTALL_PATH=/opt/pEp
PKG_NAME=pEpEngine
PKG_DESCRIPTION="p≡p Engine Binary RPM Package"
PKG_DEPENDS=sequoia-openpgp
PKG_INSTALL_PATH_STRING="/ /package/lib=${PKG_INSTALL_PATH} /package/include/pEp=${PKG_INSTALL_PATH}/include /package/share=${PKG_INSTALL_PATH}"
IS_TAGGED=${TAGGED_BUILD}
ifeq ($(IS_TAGGED), true)
# $CI_COMMIT_TAG is a predefined environment variable from Gitlab
	PEPENGINE_VERSION=${CI_COMMIT_TAG}
else
	PEPENGINE_VERSION=$(shell git rev-parse --short=8 HEAD)
endif
all: deps build test

deps:
	-docker pull --quiet $(IMAGE_NAME)-deps:latest
	cd ../../ && docker build --build-arg CURRENT_DISTRO=$(CURRENT_DISTRO) \
		      --build-arg DOCKER_REGISTRY_HOST=${DOCKER_REGISTRY_HOST} \
		      --build-arg PEPENGINE_VERSION=$(PEPENGINE_VERSION) \
		      --build-arg SEQUOIA_VERSION=$(SEQUOIA_VERSION) \
		      --build-arg YML2_VERSION=$(YML2_VERSION) \
		      --build-arg PEP_MACHINE_DIR=$(PEP_MACHINE_DIR) \
		      --cache-from $(IMAGE_NAME):latest \
		      --tag=$(IMAGE_NAME)-deps:$(SEQUOIA_VERSION)-$(YML2_VERSION) \
		      --tag=$(IMAGE_NAME)-deps:${CI_COMMIT_REF_SLUG} \
		      --tag=$(IMAGE_NAME)-deps:latest \
		      -f scripts/${CURRENT_DISTRO}/deps.$(DOCKERFILE) .
	docker push --quiet $(IMAGE_NAME)-deps:$(SEQUOIA_VERSION)-$(YML2_VERSION)
	docker push --quiet $(IMAGE_NAME)-deps:${CI_COMMIT_REF_SLUG}
	docker push --quiet $(IMAGE_NAME)-deps:latest

build:
	cd ../../ && /bin/sh ./scripts/common/build_pEpEngine.sh

test:
	cd ../../ && /bin/sh ./scripts/common/test_pEpEngine.sh

build-docker:
	-docker pull --quiet $(IMAGE_NAME):latest
	cd ../../ && docker build --build-arg CURRENT_DISTRO=$(CURRENT_DISTRO) \
		      --build-arg DOCKER_REGISTRY_HOST=${DOCKER_REGISTRY_HOST} \
		      --build-arg PEPENGINE_VERSION=$(PEPENGINE_VERSION) \
		      --build-arg SEQUOIA_VERSION=$(SEQUOIA_VERSION) \
		      --build-arg YML2_VERSION=$(YML2_VERSION) \
		      --build-arg PEP_MACHINE_DIR=$(PEP_MACHINE_DIR) \
		      --cache-from $(IMAGE_NAME):latest \
		      --tag=$(IMAGE_NAME):$(PEPENGINE_VERSION) \
		      --tag=$(IMAGE_NAME):latest \
		      -f scripts/common/build.pEpEngine.Dockerfile .
	docker push --quiet $(IMAGE_NAME):$(PEPENGINE_VERSION)
	docker push --quiet $(IMAGE_NAME):latest

rpm:
	-docker pull --quiet $(PKG_BUILD_IMAGE)-engine:latest
	@docker build --build-arg CURRENT_DISTRO=$(CURRENT_DISTRO) \
		--build-arg PEPENGINE_VERSION=$(PEPENGINE_VERSION) \
		--build-arg DOCKER_REGISTRY_HOST=${DOCKER_REGISTRY_HOST} \
		--build-arg PEP_MACHINE_DIR=$(PEP_MACHINE_DIR) \
		--build-arg PKG_INSTALL_PATH=$(PKG_INSTALL_PATH) \
		--cache-from $(PKG_BUILD_IMAGE)-engine:latest \
		--tag=$(PKG_BUILD_IMAGE)-engine:$(PEPENGINE_VERSION) \
		--tag=$(PKG_BUILD_IMAGE)-engine:latest \
		packages/rpm
	@docker push --quiet $(PKG_BUILD_IMAGE)-engine:$(PEPENGINE_VERSION)
	@docker push --quiet $(PKG_BUILD_IMAGE)-engine:latest
	@docker run -e PEPENGINE_VERSION=$(PEPENGINE_VERSION) \
		-e PEP_MACHINE_DIR=$(PEP_MACHINE_DIR) \
		-e PKG_VERSION=$(PEPENGINE_VERSION) \
		-e PKG_INSTALL_PATH=$(PKG_INSTALL_PATH) \
		-e PKG_NAME=$(PKG_NAME) \
		-e PKG_DESCRIPTION=$(PKG_DESCRIPTION) \
		-e PKG_DEPENDS=$(PKG_DEPENDS) \
		-e PKG_INSTALL_PATH_STRING=$(PKG_INSTALL_PATH_STRING) \
		--rm -v $(shell pwd)/packages/rpm/create-engine-rpm.sh:/usr/bin/create-rpm.sh:ro  \
		-v $(shell pwd)/out:/out \
		-w / $(PKG_BUILD_IMAGE)-engine:latest \
		/usr/bin/create-rpm.sh
