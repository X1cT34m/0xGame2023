echo "0xGame{Mprotect(ptr,0x1000,5)_plz_next_time_19x72bdf9}" > build/flag
docker build . -t 0xgame2023:w3t3
docker tag 0xgame2023:w3t3 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w3t3
