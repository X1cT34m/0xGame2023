echo "0xGame{N3t_cA7_M30w_9dn23hcx8}" > build/flag
echo "fIag{fAKe_fL4g}" > build/flag_fake
docker build . -t 0xgame2023:w1t0
docker tag 0xgame2023:w1t0 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w1t0
