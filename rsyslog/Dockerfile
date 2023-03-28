FROM ubuntu
RUN apt update
RUN apt install rsyslog -y
ENTRYPOINT ["rsyslogd", "-n", "-f", "/config/rsyslog.conf"]