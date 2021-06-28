PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_URL := https://github.com/alibaba/inclavare-containers/archive/v$(INCLAVARE_CONTAINERS_VERSION).tar.gz
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(INCLAVARE_CONTAINERS_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@wget -P $(RPMBUILD_DIR)/SOURCES $(RELEASE_TARBALL_URL)
endif

rpm: release-tarball
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba rpm/enclave_tls.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of enclave tls located in $(PROJECT_DIR)"

deb:
	@cd deb && ./build.sh
	@echo "the debs of enclave tls located in $(PROJECT_DIR)"

package:
ifeq (/etc/debian_version, $(wildcard /etc/debian_version))
	make deb
else ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm deb package
