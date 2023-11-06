pragma solidity ^0.8.0;

contract CasinoBackstage {
    uint number;
    uint target;

    function setnumber(uint _number) public {
        number = _number;
        target = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 114514;
    }
}

contract callsino {
    address casinoaddr;
    uint target = 1;
    uint number;
    
    constructor(address _casinoaddr) {
        casinoaddr = _casinoaddr;
    }

    function setcasino(uint _number) external {
        casinoaddr.delegatecall(abi.encodeWithSignature("setnumber(uint256)", _number));
    }

    function isSolved() external returns (bool) {
        require(number == target, "You loss!");
        return true;
    }
}