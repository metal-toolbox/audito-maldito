FROM registry.fedoraproject.org/fedora-minimal:38 AS builder

RUN microdnf install -y systemd-devel golang && microdnf clean all

WORKDIR /go/src/audito-maldito

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -o audito-maldito

# Not using distroless nor scratch because we need the systemd shared libraries
FROM registry.fedoraproject.org/fedora-minimal:38

COPY --from=builder /go/src/audito-maldito/audito-maldito /usr/bin/audito-maldito

ENTRYPOINT [ "/usr/bin/audito-maldito" ]