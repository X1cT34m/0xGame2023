echo "0xGame{N0_0n3_c4n_sTop_my_C0de_8v2yuwe7}" > build/flag-`echo $RANDOM|md5sum|cut -c 1-10`
docker build . -t 0xgame2023:w3t1
docker tag 0xgame2023:w3t1 registry.cn-hangzhou.aliyuncs.com/0xgame2023/0xgame2023:w3t1
