FROM registry.fedoraproject.org/fedora-minimal:37 AS builder

RUN microdnf install -y systemd-devel golang git && microdnf clean all

WORKDIR /go/src/audito-maldito

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o audito-maldito

# Not using distroless nor scratch because we need the systemd shared libraries
FROM registry.fedoraproject.org/fedora-minimal:37

# NOTE(jaosorior): Yes, we need to be the root user for this case.
# We need access to the journal's privileged log entries and the audit log in the future.
USER 0

COPY --from=builder /go/src/audito-maldito/audito-maldito /usr/bin/audito-maldito

ENTRYPOINT [ "/usr/bin/audito-maldito" ]
