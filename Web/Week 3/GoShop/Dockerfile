FROM golang:1.21

COPY ./src /app

WORKDIR /app

RUN echo 0xGame{eaf905e4-28a1-4006-b8a0-e8ddc2d673bf} > /flag && \
    go env -w  GOPROXY=https://goproxy.cn,direct && \
    go mod tidy && \
    go build

CMD ./GoShop