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

RUN CGO_ENABLED=0 go build -o audito-maldito

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /go/src/audito-maldito/audito-maldito /

# "NONROOT" comes from distroless:
# https://github.com/GoogleContainerTools/distroless/blob/main/base/base.bzl
USER 65532:65532

ENTRYPOINT [ "/audito-maldito" ]
