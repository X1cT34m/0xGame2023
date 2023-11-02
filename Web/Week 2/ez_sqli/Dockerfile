FROM python:3.9

COPY ./src /app

WORKDIR /app

RUN pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple flask mysqlclient

CMD python3 app.py