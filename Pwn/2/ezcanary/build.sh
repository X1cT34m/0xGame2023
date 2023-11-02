echo "0xGame{e2f82359-ac00-42a9-827e-213467ae840b}" > build/flag
docker build . -t 0xgame2023:w5t0
docker tag 0xgame2023:w5t0 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w5t0