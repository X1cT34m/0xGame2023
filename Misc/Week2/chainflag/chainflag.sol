// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract chainflag {
    address chainaddr = address(this);
    uint private lol = 114;
    uint private L0L = 514;
    uint private Lo1 = 114514;
    uint private xornum;
    bytes32[] private flag;

    constructor(uint _xornum, bytes6 _flag1, bytes6 _flag2, bytes6 _flag3, bytes6 _flag4, bytes6 _flag5) {
        xornum = _xornum;
        flag.push(_flag1 ^ bytes6(uint48(xornum)));
        flag.push(_flag2 ^ bytes6(uint48(xornum)));
        flag.push(_flag3 ^ bytes6(uint48(xornum)));
        flag.push(_flag4 ^ bytes6(uint48(xornum)));
        flag.push(_flag5 ^ bytes6(uint48(xornum)));
    }

}