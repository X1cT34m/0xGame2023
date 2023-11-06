FROM ubuntu:20.04

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev ncat
RUN python3 -m pip install -i https://mirror.nju.edu.cn/pypi/web/simple/ pyzipper

WORKDIR /app

COPY . /app

RUN chmod -R 555 /app

CMD ncat -klvp 6666 -m 999999 -e ./wrapper.sh