FROM golang:1.12.4-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
COPY . $GOPATH/src/github.com/pzduniak/caddy-basically
RUN ls $GOPATH/src/github.com/pzduniak/caddy-basically
ENV GO111MODULE on
RUN go get -v github.com/abiosoft/parent
RUN cd $GOPATH/src/github.com/pzduniak/caddy-basically && \
    go build -v github.com/pzduniak/caddy-basically
RUN ls $GOPATH/bin

FROM alpine:3.8
RUN apk add --no-cache openssh-client git
EXPOSE 80 443 2015
VOLUME /root/.caddy /srv
WORKDIR /srv
COPY --from=builder /go/bin/parent /usr/bin/parent
COPY --from=builder /go/src/github.com/pzduniak/caddy-basically/caddy-basically /usr/bin/caddy
ENTRYPOINT ["/usr/bin/parent", "caddy"]
CMD ["--conf", "/etc/Caddyfile", "--log", "stdout"]
