FROM golang:latest

RUN mkdir -p /mfa/demo
WORKDIR /mfa/demo

ADD . .
ENV GO11MODULE=on
RUN go get ./...

EXPOSE 8080
