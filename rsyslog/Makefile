.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .


.PHONY: rsyslog
rsyslog:
	docker run -ti -v `pwd`:/config -p 1514:514 -e RSYSLOG_CONF=/config/rsyslog.conf 

