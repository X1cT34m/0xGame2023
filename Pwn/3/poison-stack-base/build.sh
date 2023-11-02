echo "Now try to understand leave, you'll meet it again next week." > build/flag
echo "But as you complete this challenge, it should be a piece of cake." >> build/flag
echo "0xGame{P14y_w17h_bp_&_sp_19d8h2gf09}" >> build/flag
docker build . -t 0xgame2023:w2t4
docker tag 0xgame2023:w2t4 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w2t4
