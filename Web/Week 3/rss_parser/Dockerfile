FROM golang:1.21 as builder

COPY ./readflag.go /app/readflag.go

WORKDIR /app

RUN go build readflag.go

FROM python:3.9

COPY ./src /app

COPY --from=builder /app/readflag /readflag

WORKDIR /app

RUN pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple flask lxml requests

RUN echo 0xGame{67fd16b1-3aa5-4d83-8766-73264038184e} > /flag && \
    groupadd -r app && \
    useradd -r -g app app && \
    chmod 400 /flag && \
    chmod 4755 /readflag

USER app

CMD python3 app.py