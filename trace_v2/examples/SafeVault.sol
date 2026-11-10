// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SafeVault {
    mapping(address => uint256) public bal;
    bool private locked;
    modifier noReentrant() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external noReentrant {
        require(bal[msg.sender] >= amount, "insufficient");
        bal[msg.sender] -= amount;                 // effects before interaction (CEI)
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }
    receive() external payable {}
}
