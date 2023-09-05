# Introduction

A time-boxed security review of the **TheFund** protocol was done by **Joe Dakwa**, with a focus on the security aspects of the application's smart contracts implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# About **Joe Dakwa**

I an independent smart contract security researcher. Having found numerous security vulnerabilities in various protocols, I does my best to contribute to the blockchain ecosystem and its protocols by putting time and effort into security research & reviews. 

# About **The Fund**

The contract is serving as the underlying entity to interact with one or more third party protocols. It allows users to deposit packages into the
Fund and only whitelisted users can do so. 

## Observations

The contract Fund interacts with third party contract with IERC20 interface via busd .
The function Fund.withdrawToken interacts with third party contract with IERC20 interface via token .

## Privileged Roles & Actors

The owner is able to do the following:

    function setPackagePrice(uint newPrice) external onlyOwner 

    function setDevFee(uint256 newFee) external onlyOwner 

    function setRoot(bytes32 _root) external onlyOwner 

    function setFundAddresses(address _fund, address _dev) external onlyOwner 

    function withdrawToken(address token) external onlyOwner 

    function withdrawAll() external onlyOwner 

    function withdraw(uint256 amount) external onlyOwner 

The centralisation risks above have been addressed by Certik in a previous audit report.

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

**Impact** - the technical, economic and reputation damage of a successful attack

**Likelihood** - the chance that a particular vulnerability gets discovered and exploited

**Severity** - the overall criticality of the risk

# Security Assessment Summary

### Scope

The following smart contracts were in scope of the audit:

- `The Fund`
- `Open Zeppelin Contracts`
- `Interfaces'
- `Ownable.sol'
- 'Context.sol'
- 'MerkleProof.sol'

---

# Findings Summary

| ID     | Title                   | Severity | Status |
| ------ | ----------------------- | -------- | ------ |
| [H-01] | Owner can change price variable whilst the deposit function is executing which can result in loss of funds for early depositors. | High | TBD |
| [M-01] | endIndex and startIndex lengths are not checked leading to out of bounds access    | Medium   | TBD    |
| [M-02] | depositsOfOwnerInRange does not check if the user has any deposits | Medium | TBD |
| [L-02] | Use a two-step ownership transfer approach | Low | TBD |
| [G-01] | Use unchecked in for loops | Gas | TBD |
| [G-02] | Use calldata instead of memory | Gas | TBD |
| [G-03] | Use custom errors where possible | Gas | TBD |

# Detailed Findings

# [H-01] Owner can change price variable whilst the deposit function is executing which can result in lossof funds for early depositors.

## Severity

**Impact:** High, because early depositors will lose out anytime before fee structure is changed

**Likelihood:** Medium, because there is responsibility on the owner to set the fee structure, which will happen in real time

## Description

In function deposit, users deposit packages into the fund.

Once deposited, the fund stores the package and deposit info in the deposits array.

'''
// store deposited package amount on storage
        deposits[id] = DepositInfo(_msgSender(), amount, busdAmount, block.timestamp);
'''

The public price variable of 250 eth, prior to this, is checked against the amount of BUSD sent by the user.

'''
   // total BUSD deposited
        uint256 busdAmount = amount * price;
'''

However, the vulnerability comes from the fact that before the transaction is completed, 
the owner can change the price variable.

'''solidity

    function setPackagePrice(uint newPrice) external onlyOwner {
        require(newPrice > 0, 'Zero Price');
        price = newPrice;
    }
'''

The user will receive a notifcation that their transaction completed with the assumption
that the price was fixed at 250 ETH.

But lets say the owner increases the price to 500 ETH, the users initial balance will be lower than 
the amount of BUSD they sent.

## Recommendations

Fetch the current price variable before calculating the total of BUSD deposited.

'''
  // Retrieve the current price
    uint256 currentPrice = price;
'''

Then, check if the price has changed before the deposit process and revert if so.

'''
    // Check if the price has changed during the deposit process
    if (currentPrice != price) {
        revert("Price has changed during deposit");
    }
'''

# [M-01] endIndex and startIndex lengths are not checked leading to out of bounds access


## Severity

**Impact:** High, because this will result in unexpected values not processed

**Likelihood:** Low, because it will take some time for both values to possibly exceed the expected values

## Description

In depositsOfOwnerInRange, the function loops through the deposits array and returns the deposits
for a given user.

However, function does not sufficiently validate the input parameters startIndex and endIndex. 
Without proper validation, these values can be manipulated, leading to unexpected behavior or errors.

uint256 length = endIndex - startIndex;

## Recommendations

Consider adding the below, before the division calculation difference check to the function that checks if the startIndex and endIndex are within the bounds of the deposits array. Then you can conduct the division.

'''require(startIndex <= endIndex, "Invalid range");'''

Then you can add the rest of the below logic to further validate the input parameters.

'''
  uint256 userDepositCount = userIDs[owner].length;
    require(endIndex <= userDepositCount, "End index exceeds user's deposit count");
    
    uint256 length = endIndex - startIndex;
    DepositInfo[] memory userDeposits = new DepositInfo[](length);
'''

The function should look something like this:

'''solidity
function depositsOfOwnerInRange(address owner, uint startIndex, uint endIndex) external view returns (DepositInfo[] memory) {
    require(startIndex <= endIndex, "Invalid range");
    
    uint256 userDepositCount = userIDs[owner].length;
    require(endIndex <= userDepositCount, "End index exceeds user's deposit count");
    
    uint256 length = endIndex - startIndex;
    DepositInfo[] memory userDeposits = new DepositInfo[](length);

    for (uint256 i = startIndex; i < endIndex; i++) {
        // Check if a deposit exists for this ID
        if (i < userDepositCount) {
            userDeposits[i - startIndex] = deposits[userIDs[owner][i]];
        }
    }

    return userDeposits;
}
'''


# [M-02] depositsOfOwnerInRange does not check if the user has any deposits

## Severity

**Impact:** High, because this will result in the array not checking, due to everytime the function is called

**Likelihood:** Low, because its only a view function, with a risk of DOS if called excessively.

## Description

In '''depositsOfOwnerInRange''', the function loops through the deposits array and returns the deposits.

The current implementation of the depositsOfOwnerInRange function does not check whether a 
deposit exists for a particular ID. As a result, if there are gaps in the deposit IDs 
(e.g., if some deposits have been deleted), the resulting array may contain uninitialized or empty elements.

The loop used to retrieve deposit information does not check whether a deposit exists for a particular ID. 
As a result, if there are gaps in the deposit IDs (e.g., if some deposits have been deleted), 
the resulting array may contain uninitialized or empty elements.

## Recommendations


Consider adding a check to the loop that checks if the deposit exists for a particular ID.

'''
if (i < userDepositCount) {
        userDeposits[i - startIndex] = deposits[userIDs[owner][i]];
    }
'''

This is issue links in with the above [M-01]

# [M-03] Missing return values on BNB transfer

## Severity

**Impact:** High, because this will result in failure of verifying return values

**Likelihood:** Medium, as this will likely happen from time to time without checking

## Description

During the ```purchaseItem``` function, there is an external call to transfer the fee to the marketplace owner.

```solidity
        //send Fee to Markeplace owner
        feeAccount.transfer(_totalPrice * feePercent / 1000);

        and 
        //send saleFee
        payable(item.seller).transfer(_item[i].price * (1000-feePercent) / 1000);
```

However, there is no check to see if the transfer was successful.

If using BNB, it (transfer) will not return a bool on erc20 methods. Missing a return value.
https://twitter.com/Uniswap/status/1072286773554876416


If the transaction reverts after the marketplace owner's fee has been deducted but before the transaction is completed, you might end up in an inconsistent state where the fee has been taken from the buyer but hasn't been received by the marketplace owner.

If the transfer of funds to the seller reverts, the buyer would lose their funds without receiving the NFT, and the seller would not receive their payment.

## Recommendations


Its important to use the .call method when calling external contracts, and check the return value, rather than ```.transfer```.

For example:

```solidity
// Sending fee to marketplace owner
(bool feeTransferSuccess, ) = feeAccount.call{value: _totalPrice * feePercent / 1000}("");
require(feeTransferSuccess, "Fee transfer failed");

// Sending sale fee to seller
(bool saleFeeTransferSuccess, ) = payable(item.seller).call{value: _item[i].price * (1000-feePercent) / 1000}("");
require(saleFeeTransferSuccess, "Sale fee transfer failed");
```

Keep in mind ```.call``` can open up for reentrancy attacks, so alteratively use Open Zeppellins ```sendValue``` method.

# [M-04] transferFrom doesnt revert the transaction upon failure

## Severity

**Impact:** High, because this will result in loss of funds

**Likelihood:** Medium, as this will likely happen from time to time without checking

## Description

In the purchaseItem function, there is a call to transfer the NFT from the seller to the buyer.

```solidity
        //transfer NFT to buyer
        _nft.transferFrom(seller, msg.sender, id);
```

However, if this transfer fails, the transaction will not revert.

This means that the buyer will lose their funds, but will not receive the NFT. As the mapping of the item to the buyer will not be updated, as its been deleted from the items array.

## Recommendations

Use Open Zeppellins SafeERC20 library, which will revert the transaction if the transfer fails.

```_nft.safeTransferFrom(seller, msg.sender, id);```

# [M-05] Block gas limit can be reached in purchaseItem

## Severity

**Impact:** High, because this will result in failed transactions

**Likelihood:** Medium, as this will likely happen almost everytime the ```purchaseItem``` function call

## Description

In the ```purchaseItem``` function, there are 2 for loops, which iterate over the items array.

There are several state changes taking place in this function, which will result in higher gas fees than usual.

When the items array is large, this could result in the block gas limit being reached, which would result in the transaction failing.

## Recommendations

Combine multiple operations into a single loop to reduce the number of iterations. For instance, batch the transfer of NFTs and payments to sellers together in a single loop.

# [L-01] Locking the contract forever is possible

## Severity

**Impact:** High, because this will result in locked contract

**Likelihood:** Low, although care is assumed, mitigation here is a must and there is a chance of the wrong address being passed in

## Description

There is no check that the address of the new owner is the zero address.

If the current owner deliberately or accidently sets the new owner to the zero address, the contract will be permanently locked.

```solidity
  function changeOwner (address _newOwner) public {
        require(msg.sender == owner, "Not Owner");
        owner = _newOwner;
    }
```

## Recommendations

Add a require statement that prevents the new owner from being the zero address.

```require(_newOwner != address(0), "New owner cannot be zero address");```


# [L-02] Use a two-step ownership transfer approach

## Severity

**Impact:** Medium, because this will result in accidently tranfering ownership to an address not desired

**Likelihood:** Low, although care is assumed, mitigation here is a must and there is a chance of the wrong address being passed in

## Description

When transfering ownership, please use Open Zeppelin's Ownable contract and import it into the contract.

Specifically the Ownable2Step contract.

## Recommendations

As it gives you the security of not unintentionally sending the owner role to an address you do not control.

See below current implementation.

```solidity
  function changeOwner (address _newOwner) public {
        require(msg.sender == owner, "Not Owner");
        owner = _newOwner;
    }
```

By using the Ownable2Step library this ensures you are following the industry best practices.

# [G-01] Use unchecked in for loops 


## Description

Use unchecked for arithmetic where you are sure it won't over or underflow, 
saving gas costs for checks added from solidity v0.8.0.

In the example below, the variable i cannot overflow because of the condition i < length, where length is defined as uint256. The maximum value i can reach is max(uint)-1. 

Thus, incrementing i inside unchecked block is safe and consumes lesser gas.

```solidity
function loop(uint256 length) public {
	for (uint256 i = 0; i < length; ) {
	    // do something
	    unchecked {
	        i++;
	    }
	}
}
```

## Recommendations

In function ```purchaseItem``` implement these changes into the for loop.

# [G-02] Use calldata instead of memory

## Description

It is generally cheaper to load variables directly from calldata, rather than copying them to memory. Only use memory if the variable needs to be modified.


## Recommendations

```solidity
    function listItem(Item memory _item) external nonReentrant 
```

Change to:

```solidity
    function listItem(Item calldata _item) external nonReentrant 
```

# [G-03] Use custom errors where possible

## Severity

**Impact:** Medium, because this will result in accidently tranfering ownership to an address not desired

**Likelihood:** Low, although care is assumed, mitigation here is a must and there is a chance of the wrong address being passed in

## Description

Instead of using strings for error messages (e.g., require(msg.sender == owner, “unauthorized”)), you can use custom errors to reduce both deployment and runtime gas costs. In addition, they are very convenient as you can easily pass dynamic information to them.

## Recommendations


Use custom errors where possible, as they are cheaper than revert.
```solidity
            require(item.seller != address(0), "item doesn't exist");
```
Change to:

List the error in the contract body:

```error ItemDoesNotExist(uint256 id);```

Then use it in the require statement:

```require(item.seller != address(0))```

```revert ItemDoesNotExist(id);```



