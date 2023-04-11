FROM golang:1.20 as builder

WORKDIR /go/src/audito-maldito

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY ingesters ./ingesters
COPY internal ./internal
COPY processors ./processors
COPY main.go .

RUN go build -o audito-maldito

# Not using distroless nor scratch because we need the systemd shared libraries
FROM alpine:3.17.3
# NOTE(jaosorior): Yes, we need to be the root user for this case.
# We need access to the journal's privileged log entries and the audit log in the future.
USER 0

COPY --from=builder /go/src/audito-maldito/audito-maldito /usr/bin/audito-maldito

ENTRYPOINT [ "/usr/bin/audito-maldito" ]