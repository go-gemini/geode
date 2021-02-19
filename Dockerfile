# Stage 1: Build the application
FROM golang:1.16-buster as builder

RUN mkdir /build

WORKDIR /usr/src/geode

ADD ./go.mod ./go.sum ./
RUN go mod download

ADD . ./

RUN go build -v -o /build/geode

# Stage 2: Copy files and configure what we need
FROM debian:buster-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the built seabird into the container
COPY --from=builder /build/geode /usr/local/bin

VOLUME /var/lib/geode
WORKDIR /var/lib/geode

CMD ["/usr/local/bin/geode"]
