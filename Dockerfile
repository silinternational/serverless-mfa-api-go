FROM golang:1.21

RUN curl -o- -L https://slss.io/install | VERSION=3.36.0 bash && \
  mv $HOME/.serverless/bin/serverless /usr/local/bin && \
  ln -s /usr/local/bin/serverless /usr/local/bin/sls

WORKDIR /src

RUN curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

COPY ./ .
RUN go get ./...

EXPOSE 8080

CMD ["air"]
