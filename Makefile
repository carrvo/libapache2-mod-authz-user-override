# Location of apxs command:
#APXS=apxs2
APXS=apxs

version = $(error version is not set)

.DEFAULT_GOAL:= build
.PHONY: install build clean

install: mod_authz_user_override.la
	$(APXS) -i -a mod_authz_user_override.la

build: mod_authz_user_override.la

mod_authz_user_override.la: mod_authz_user_override.c
	$(APXS) -c mod_authz_user_override.c

clean:
	rm -rf mod_authz_user_override.so mod_authz_user_override.o \
	    mod_authz_user_override.la mod_authz_user_override.slo \
	    mod_authz_user_override.lo .libs
	-ls -a .*.swp
	sudo rm -Rf package

debian-package-dependencies:
	sudo apt install build-essential fakeroot devscripts apache2-dev dupload

debian-package-version:
	dch -v $(version)

debian-package:
	debuild -us -uc -Zxz
	mkdir package || true
	mv ../libapache2-mod-authz-user-override_* package/

debsign:
	cd package && debsign libapache2-mod-authz-user-override_$(version)_amd64.changes

dupload:
	cd package && dupload --to debian-mentors
