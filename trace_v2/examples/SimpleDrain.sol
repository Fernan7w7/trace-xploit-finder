// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SimpleDrain {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external { // BUG: no balance check
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }
    receive() external payable {}
}
