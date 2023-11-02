FROM golang:1.21 as builder

COPY ./readflag.go /app/readflag.go

WORKDIR /app

RUN go build readflag.go

FROM tomcat:8.5-jdk8

COPY ./ROOT.war /usr/local/tomcat/webapps/

COPY --from=builder /app/readflag /readflag

RUN echo 0xGame{ff87729b-b100-4965-9ed4-b6c0478c76f7} > /flag && \
    groupadd -r tomcat && \
    useradd -r -g tomcat tomcat && \
    chown -R tomcat:tomcat /usr/local/tomcat/ && \
    chmod 400 /flag && \
    chmod 4755 /readflag

USER tomcat