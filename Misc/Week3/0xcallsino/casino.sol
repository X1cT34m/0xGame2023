pragma solidity ^0.8.0;

contract CasinoBackstage {
    uint number;
    uint target;

    function setnumber(uint _number) public {
        number = _number;
        target = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 114514;
    }
}