echo "0xGame{edf1f8de-66cc-43d5-9a30-9067371ca77a}" > build/flag
docker build . -t 0xgame2023:w5t1
docker tag 0xgame2023:w5t1 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w5t1