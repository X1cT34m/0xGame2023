FROM php:7.4-apache

COPY ./src /var/www/html

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org/debian-security|mirrors.ustc.edu.cn/debian-security|g' /etc/apt/sources.list && \
    apt update && \
    apt install -y net-tools iputils-ping && \
    echo 0xGame{19c71976-d7d8-4ab8-9ea5-6ea3800f59f6} > /flag