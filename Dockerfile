FROM golang:latest

WORKDIR /mfa

RUN curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

ADD . .
ENV GO11MODULE=on
RUN go get ./...

EXPOSE 8080

CMD ["air"]