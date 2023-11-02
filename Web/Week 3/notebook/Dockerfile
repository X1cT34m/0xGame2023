FROM python:3.11

COPY ./src /app

WORKDIR /app

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple flask && \
    echo 0xGame{750fdbdf-1155-4cac-818e-8918a6ff0bf4} > /flag

CMD python3 app.py