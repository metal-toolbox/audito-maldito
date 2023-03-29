.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .

.PHONY: rsyslog
rsyslog:
	docker rm rsyslog && \
	docker run --name rsyslog -ti -v ${PWD}/config:/config -v /var/log/audit/:/var/log/audit/ -e RSYSLOG_CONF=/config/rsyslog.conf  ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1


