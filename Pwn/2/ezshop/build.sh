echo "0xGame{f78ad928-29c4-4268-bd80-4fa970456c92}" > build/flag
docker build . -t 0xgame2023:w5t2
docker tag 0xgame2023:w5t2 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w5t2