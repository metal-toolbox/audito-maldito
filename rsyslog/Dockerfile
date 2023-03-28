FROM ubuntu
RUN apt update
RUN apt install rsyslog -y
RUN apt install libcurl4 -y
RUN mkdir -p /usr/lib/x86_64-linux-gnu/rsyslog
COPY libs/omhttp.so /usr/lib/x86_64-linux-gnu/rsyslog/
COPY libs/libcurl-gnutls.so.4 /usr/lib/x86_64-linux-gnu/
ENTRYPOINT ["rsyslogd", "-n", "-f", "/config/rsyslog.conf"]