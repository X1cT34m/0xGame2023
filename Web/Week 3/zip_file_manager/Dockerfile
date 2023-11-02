FROM python:3.11

COPY ./src /app

WORKDIR /app

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple flask && \
    echo 0xGame{2fc76ab2-aa2f-441d-9143-210150fabce9} > /flag

CMD python3 app.py