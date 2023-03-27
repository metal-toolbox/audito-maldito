FROM registry.fedoraproject.org/fedora-minimal:37

RUN microdnf install -y systemd-devel golang git && microdnf clean all

WORKDIR /go/src/audito-maldito

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p ~/go/src/github.com/go-delve
WORKDIR /root/go/src/github.com/go-delve
RUN git clone https://github.com/go-delve/delve 
RUN cd delve && go install github.com/go-delve/delve/cmd/dlv
WORKDIR /go/src/audito-maldito
EXPOSE 2345

#ENTRYPOINT ["-c", "/root/go/bin/dlv",  "debug",  ".", "--headless"  "--listen=:2345" "--log" ]
