FROM golang:1.18

RUN curl -o- -L --proto "=https" https://slss.io/install | VERSION=3.7.5 bash && \
  mv $HOME/.serverless/bin/serverless /usr/local/bin && \
  ln -s /usr/local/bin/serverless /usr/local/bin/sls

WORKDIR /src

RUN curl -sSfL --proto "=https" https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | \
    sh -s -- -b $(go env GOPATH)/bin

COPY ./ .
RUN go get ./...

EXPOSE 8080

CMD ["air"]
