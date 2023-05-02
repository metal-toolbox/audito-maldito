# Rsyslog
Rsyslog provides an easy abstraction of reading logs from multiple linux distributions. Rsyslog can be integrated with `audito-maldito` easily by writing the rsyslog ingested logs to a named pipe. Example [rsyslog config](config/rsyslog.conf). Create an ingester struct in `audito-maltio` that uses the `NamedPipeIngester` to ingest logs from the named pipe rsyslog is writing to. See [AuditLogIngester](../ingesters/auditlog/auditlogingester.go) for an example. Create a `Process` func to parse the incoming log messages.



## Build
```
go build . && make image && make rsyslog
```

## Deployment
The intent of the rsyslog image is to run the rsyslog container inside the `audito-maldito` pod. An individual can use the default [rsyslong.conf](config/rsyslog.conf) and default [rsyslog.d](./config/rsyslog.d/) files or mount custom configurations to these locations via a `VolumeMount` in k8s.