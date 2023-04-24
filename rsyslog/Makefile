IMAGE=ghcr.io/metal-toolbox/audito-maldito
TAG=latest

.PHONY: image
image:
	docker build -t $(IMAGE)-rsyslog:$(TAG) .

.PHONY: rsyslog
rsyslog:
	docker run -ti \
	--name rsyslog \
	-v /run/systemd/journal:/run/systemd/journal \
	-v /var/log:/var/log \
	-v /etc/machine-id:/etc/machine-id \
	-v ${PWD}/config/rsyslog.conf:/etc/rsyslog.conf \
	-v ${PWD}/config/rsyslog.d:/etc/rsyslog.d \
	 $(IMAGE)-rsyslog:$(TAG)