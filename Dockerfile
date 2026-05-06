FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
ARG REPO_URL=https://github.com/Abdoun1m/dmz_collector
ARG REPO_BRANCH=main
RUN git clone --branch ${REPO_BRANCH} ${REPO_URL} /src
WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/dmz-collector ./cmd/dmz-collector

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -H dmzcollector
RUN mkdir -p /data/spool && chown -R dmzcollector:dmzcollector /data
COPY --from=builder /out/dmz-collector /usr/local/bin/dmz-collector
USER dmzcollector
EXPOSE 9000/tcp
EXPOSE 5514/udp
ENTRYPOINT ["/usr/local/bin/dmz-collector"]

