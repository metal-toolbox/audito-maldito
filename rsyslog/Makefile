.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .

.PHONY: rsyslog
rsyslog:
	docker rm -f rsyslog && \
	docker run -ti \
	--name rsyslog \
	-v /run/systemd/journal:/run/systemd/journal \
	-v /var/log:/var/log \
	-v /etc/machine-id:/etc/machine-id:ro \
	-v ${PWD}/config/rsyslog.conf:/etc/rsyslog.conf:ro \
	-v ${PWD}/config/rsyslog.d:/etc/rsyslog.d \
	 ghcr.io/angrieralien/audito-maldito:named-pipe-abstraction-rsyslog

.PHONY: am
am:
	docker run  -ti \
	--name am  \
	-v /var/log:/var/log\
	-v /etc/machine-id:/etc/machine-id:ro \
	-v /etc/os-release:/etc/os-release:ro \
	-v /app-audit:/app-audit \
	 ghcr.io/angrieralien/audito-maldito:named-pipe-abstraction