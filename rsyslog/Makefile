.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .

.PHONY: rsyslog
rsyslog:
	docker rm rsyslog && \
	docker run --name rsyslog -p 2345:2345 -ti -v ${PWD}/config:/config -v /var/log/audit/:/var/log/audit/ -v /var/log/journal/:/var/log/journal -e RSYSLOG_CONF=/config/rsyslog.conf  ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1


