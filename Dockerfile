FROM registry.fedoraproject.org/fedora-minimal:36

RUN microdnf install -y systemd-devel golang && microdnf clean all

WORKDIR /go/src/audito-maldito

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -o /usr/bin/audito-maldito