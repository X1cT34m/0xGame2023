// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Void {
  constructor() {}
}

contract TestLuck {
  address payable owner;
  bool solved;

  constructor(address payable _owner) {
    owner = _owner;
  }

  modifier OnlyYou {
    require(uint256(uint160(msg.sender)) % 50 == 20, "NoNo!!");
    _;
  }
  
  function makevoid() external {
    Void v = new Void();
  }

  function checkyourluck() external OnlyYou {
    Void v = new Void();
    if(uint256(uint160(address(v))) % 50 == 30) {
      solved = true;
    }
    else {
      selfdestruct(owner);
    }
  }

  function isSolved() external returns (bool) {
    return solved;
  }
}