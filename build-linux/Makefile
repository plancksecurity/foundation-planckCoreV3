#------------------------------------------------------------------------------#
# Makefile to build libEtpan GPGME, GnuPG and deps for use with pEpEngine 
#  based on pEpJNIAdapter/android/external/Makefile
#------------------------------------------------------------------------------#

all: build 

build: libetpan-install gnupg-install gpgme-install

PREFIX ?= $(HOME)

CFLAGS = 
LDFLAGS = 

#------------------------------------------------------------------------------#
# libgpg-error

EXTERNAL_GIT_REPOS += libgpg-error|git://git.gnupg.org/libgpg-error.git?libgpg-error-1.20

libgpg-error/configure: libgpg-error.src.stamp libgpg-error/configure.ac 
	cd libgpg-error && ./autogen.sh

libgpg-error/Makefile: libgpg-error/configure 
	cd libgpg-error && \
		./configure \
			CFLAGS="$(CFLAGS)" \
			LDFLAGS="$(LDFLAGS)" \
			--disable-doc \
			--disable-languages \
			--prefix=$(PREFIX)
	ls -l libgpg-error/libtool

libgpg-error/src/.libs/libgpg-error.so: libgpg-error/Makefile 
	$(MAKE) -C libgpg-error

libgpg-error-build: libgpg-error/src/.libs/libgpg-error.so

$(PREFIX)/lib/libgpg-error.so: libgpg-error/src/.libs/libgpg-error.so
	$(MAKE) -C libgpg-error prefix=$(PREFIX) install
	ls -l $(PREFIX)/lib/libgpg-error.so*

libgpg-error-install: $(PREFIX)/lib/libgpg-error.so

#------------------------------------------------------------------------------#
# libgcrypt

EXTERNAL_GIT_REPOS += libgcrypt|git://git.gnupg.org/libgcrypt.git?libgcrypt-1.6.4

libgcrypt/configure: libgcrypt.src.stamp libgcrypt/configure.ac 
	cd libgcrypt && ./autogen.sh

libgcrypt/Makefile: libgcrypt/configure 
	cd libgcrypt && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--enable-maintainer-mode \
				--with-gpg-error-prefix=$(PREFIX) \
				--prefix=$(PREFIX)

libgcrypt/src/.libs/libgcrypt.so: $(PREFIX)/lib/libgpg-error.so libgcrypt/Makefile
	$(MAKE) -C libgcrypt

$(PREFIX)/lib/libgcrypt.so: libgcrypt/src/.libs/libgcrypt.so
	$(MAKE) -C libgcrypt prefix=$(PREFIX) install
	ls -l $(PREFIX)/lib/libgcrypt.so

libgcrypt-build: libgcrypt/src/.libs/libgcrypt.so

libgcrypt-install: $(PREFIX)/lib/libgcrypt.so

#------------------------------------------------------------------------------#
# libassuan

EXTERNAL_GIT_REPOS += libassuan|git://git.gnupg.org/libassuan.git?libassuan-2.3.0

libassuan/configure: libassuan.src.stamp libassuan/configure.ac 
	cd libassuan && ./autogen.sh && autoreconf --install --force --verbose

libassuan/Makefile: libassuan/configure
	cd libassuan && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--enable-maintainer-mode \
				--with-gpg-error-prefix=$(PREFIX) \
				--prefix=$(PREFIX)

libassuan/src/.libs/libassuan.so: $(PREFIX)/lib/libgpg-error.so libassuan/Makefile
	$(MAKE) -C libassuan

$(PREFIX)/lib/libassuan.so: libassuan/src/.libs/libassuan.so
	$(MAKE) -C libassuan prefix=$(PREFIX) install
	ls -l $(PREFIX)/lib/libassuan.so

libassuan-build: libassuan/src/.libs/libassuan.so

libassuan-install: $(PREFIX)/lib/libassuan.so

#------------------------------------------------------------------------------#
# libksba

EXTERNAL_GIT_REPOS += libksba|git://git.gnupg.org/libksba.git?libksba-1.3.3

libksba/configure: libksba.src.stamp libksba/configure.ac 
	cd libksba && ./autogen.sh

libksba/Makefile: $(PREFIX)/lib/libgpg-error.so libksba/configure
	cd libksba && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--enable-maintainer-mode \
				--with-gpg-error-prefix=$(PREFIX) \
				--prefix=$(PREFIX)

libksba/src/.libs/libksba.so: libksba/Makefile
	$(MAKE) -C libksba

$(PREFIX)/lib/libksba.so: libksba/src/.libs/libksba.so
	$(MAKE) -C libksba prefix=$(PREFIX) install
	ls -l $(PREFIX)/lib/libksba.so

libksba-build: libksba/src/.libs/libksba.so

libksba-install: $(PREFIX)/lib/libksba.so

#------------------------------------------------------------------------------#
# curl

EXTERNAL_GIT_REPOS += curl|https://github.com/bagder/curl?curl-7_45_0

curl/configure: curl.src.stamp curl/configure.ac 
	cd curl && ./buildconf

curl/Makefile: curl/configure
	cd curl && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--prefix=$(PREFIX) \
				--with-gnu-ld \
				--disable-imap \
				--disable-ldap \
				--disable-pop3 \
				--disable-rtsp \
				--disable-smtp

curl/lib/.libs/libcurl.so: curl/Makefile
	$(MAKE) -C curl

$(PREFIX)/lib/libcurl.so: curl/lib/.libs/libcurl.so
	$(MAKE) -C curl prefix=$(PREFIX) install
	ls -l $(PREFIX)/lib/libcurl.so

curl-build: curl/lib/.libs/libcurl.so

curl-install: $(PREFIX)/lib/libcurl.so


#------------------------------------------------------------------------------#
# gnupg

EXTERNAL_GIT_REPOS += gnupg|git://git.gnupg.org/gnupg.git?gnupg-2.0.29

gnupg/configure: gnupg.src.stamp gnupg/configure.ac 
	-sed -i '/^tests/d' gnupg/configure.ac
	-sed -i 's/tests = tests/tests =/' gnupg/Makefile.am
	cd gnupg && ./autogen.sh

gnupg/Makefile: gnupg/configure
	cd gnupg && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--enable-maintainer-mode \
				--with-gpg-error-prefix=$(PREFIX) \
				--with-libgcrypt-prefix=$(PREFIX) \
				--with-libassuan-prefix=$(PREFIX) \
				--with-ksba-prefix=$(PREFIX) \
				--with-libcurl=$(PREFIX) \
				--disable-agent \
				--disable-scdaemon \
				--disable-ldap \
				--disable-doc \
				--disable-gpgsm \
				--prefix=$(PREFIX)

gnupg/g10/gpg2: $(PREFIX)/lib/libgpg-error.so $(PREFIX)/lib/libgcrypt.so $(PREFIX)/lib/libksba.so $(PREFIX)/lib/libassuan.so $(PREFIX)/lib/libcurl.so gnupg/Makefile
	$(MAKE) -C gnupg

$(PREFIX)/bin/gpg2: gnupg/g10/gpg2 gnupg/configure
	$(MAKE) -C gnupg prefix=$(PREFIX) install
	ls -l $(PREFIX)/bin/gpg2

gnupg-build: gnupg/g10/gpg2

gnupg-install: $(PREFIX)/bin/gpg2

#------------------------------------------------------------------------------#
# gpgme

EXTERNAL_GIT_REPOS += gpgme|git://git.gnupg.org/gpgme.git?gpgme-1.6.0

gpgme/configure: gpgme.src.stamp gpgme/configure.ac 
	cd gpgme && ./autogen.sh 

gpgme/Makefile: gpgme/configure
	cd gpgme && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--enable-maintainer-mode \
				--with-gpg-error-prefix=$(PREFIX) \
				--with-libassuan-prefix=$(PREFIX) \
				--enable-fixed-path=$(PREFIX)/bin \
				--without-g13 \
				--disable-glibtest \
				--disable-gpg-test \
				--disable-gpgsm-test \
				--disable-gpgconf-test \
				--disable-parallel-test \
				--disable-g13-test \
				--prefix=$(PREFIX)


gpgme/src/.libs/libgpgme.so: gpgme/Makefile
	$(MAKE) -C gpgme

$(PREFIX)/lib/libgpgme.so: gpgme/src/.libs/libgpgme.so
	$(MAKE) -C gpgme prefix=$(PREFIX) install

gpgme-build: gpgme/src/.libs/libgpgme.so

gpgme-install: $(PREFIX)/bin/gpg2 $(PREFIX)/lib/libgpgme.so

#------------------------------------------------------------------------------#
# libetpan

EXTERNAL_GIT_REPOS += libetpan|https://github.com/fdik/libetpan.git?HEAD

libetpan/configure: libetpan.src.stamp
	cd libetpan && ./autogen.sh

libetpan/Makefile: libetpan/configure
	cd libetpan && \
		CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
			./configure \
				--prefix=$(PREFIX)

libetpan/src/.libs/libetpan.so: libetpan/Makefile
	$(MAKE) -C libetpan

$(PREFIX)/lib/libetpan.so: libetpan/src/.libs/libetpan.so
	$(MAKE) -C libetpan install

libetpan-build: libetpan/src/.libs/libetpan.so

libetpan-install: $(PREFIX)/lib/libetpan.so

#------------------------------------------------------------------------------#
# Clone update and archive external projects GIT repos
# Local clone is in external/$project.git while 
# selected commit is archived in external/$project

define per_repo_targets
$(1).git.stamp:
	git clone $(2) $(1).git
	touch $(1).git.stamp

$(1).git_update: $(1).git.stamp
	cd $(1).git; git pull
	touch $(1).git.stamp

$(1).src.stamp: $(1).git.stamp
	rm -rf $(1)
	mkdir $(1)
	(cd $(1).git; git archive --format=tar $(3)) | tar -C $(1) -x
	touch $(1).src.stamp

$(1)-src: $(1).src.stamp

$(1)-clean: 
	rm -rf $(1)
	rm -f $(1).src.stamp

EXTERNAL_LOCAL_GITS += $(1).git.stamp
EXTERNAL_LOCAL_GITS_UPDATE += $(1).git_update
EXTERNAL_SRCS += $(1)-src
EXTERNAL_SRCS_CLEAN += $(1)-clean
endef

define per_repo
$(call per_repo_targets,\
    $(1),\
    $(word 1,$(subst ?, ,$(2))),\
    $(word 2,$(subst ?, ,$(2))))
endef

$(foreach repo, $(EXTERNAL_GIT_REPOS), $(eval $(call per_repo,\
    $(word 1,$(subst |, ,$(repo))),\
    $(word 2,$(subst |, ,$(repo))))))

git_clones: $(EXTERNAL_LOCAL_GITS)

git_update: $(EXTERNAL_LOCAL_GITS_UPDATE)

#------------------------------------------------------------------------------#
# clean

clean: $(EXTERNAL_SRCS_CLEAN) clean-install libetpan-cleanzip

#------------------------------------------------------------------------------#

.PHONY = clean clean-install libetpan-cleanzip\
	libgpg-error-build libgpg-error-install \
	libgcrypt-build libgcrypt-install \
	libassuan-build libassuan-install \
	libksba-build libksba-install \
	gnupg-build  gnupg-install\
	gpgme-build  gpgme-install\
	curl-build curl-install \
	clean-install \
    $(EXTERNAL_LOCAL_GITS_UPDATE) $(EXTERNAL_SRCS) $(EXTERNAL_SRCS_CLEAN) \
	showsetup

