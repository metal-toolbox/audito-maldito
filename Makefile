.PHONY: all
all: image run-test

.PHONY: image
image:
	docker build -t localbuild/audito-maldito:latest .

.PHONY: run-test
run-test:
	docker run -ti \
		-v $$PWD/journal:/var/log/journal/b3f9b6f421fc4af5b8770b54ebceb5ca/system.journal:ro \
		-v $$PWD/machine-id:/etc/machine-id:ro \
		-v $$PWD/machine-id:/var/lib/dbus/machine-id:ro \
		localbuild/audito-maldito:latest /usr/bin/audito-maldito --boot-id 050f00188b4b425592e35d0146cbf043
