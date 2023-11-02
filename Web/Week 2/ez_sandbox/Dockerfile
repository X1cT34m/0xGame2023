FROM node:18

COPY ./src /app

WORKDIR /app

RUN echo 0xGame{fcd263b5-a739-41f8-a58f-7851c88b2f79} > /flag && \
    npm --registry https://registry.npmmirror.com/ install express express-session body-parser

CMD node app.js