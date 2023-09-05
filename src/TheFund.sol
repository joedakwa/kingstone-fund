pragma solidity 0.8.14;

error ZeroAddress();
error ZeroAmount();
error VerifyFailed();

contract Fund is Ownable {
    /// @dev price per one package
    uint256 public price = 250 ether;
    /// @dev BUSD smart contract address
    IERC20 public immutable busd;
    /// @dev total deposited package amount
    uint256 public total;
    ///@dev total BUSD deposited
    uint256 public totalBUSD;
    /// @dev current deposit id
    uint256 private id;
    /// @dev fund will be withdrawn to fund wallet
    address public fund;
    /// @dev 2% development fee will be sent to dev wallet
    address public dev;
    /// @dev dev fee charged
    uint256 public devFee;
    /// @dev merkle tree root to set whitelisted users
    bytes32 private root;

    struct DepositInfo {
        address owner;
        uint256 numPackages;
        uint256 amountBUSD;
        uint256 timestamp;
    }
    mapping(uint256 => DepositInfo) public deposits;

    // mapping from an address to a list of deposit IDs
    mapping ( address => uint256[] ) public userIDs;

    /* ==================== EVENTS ==================== */

    event Deposit(address indexed from, uint256 numPackages, uint256 busdAmount);
    event Withdraw(address indexed fund, uint256 fundAmount, address dev, uint256 devAmount);
    event SetMerkleTreeRoot(address indexed from, bytes32 root);

    /* ==================== METHODS ==================== */

    /**
     * @dev constructor
     *
     * BUSD mainnet: 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56
     * BUSD testnet: 0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee
     * @param _busd BUSD smart contract address
     * @param _fund main team fund wallet address
     * @param _dev dev team wallet address
     */
    constructor(address _busd, address _fund, address _dev) {
        if (_busd == address(0) || _fund == address(0) || _dev == address(0))
            revert ZeroAddress();

        busd = IERC20(_busd);
        fund = _fund;
        dev = _dev;
    }

    /**
     * @dev user can deposit at least 1 package, only whitelisted users are able to deposit
     * @param amount package amount
     */
     //@audit
    function deposit(uint256 amount, bytes32[] calldata proof) external {
        // amount should be bigger than zero
        if (amount == 0) revert ZeroAmount();

        // check if caller is whitelisted
        if (!checkWhitelist(proof)) revert VerifyFailed();

        // total BUSD deposited
        uint256 busdAmount = amount * price;

        // store deposited package amount on storage
        deposits[id] = DepositInfo(_msgSender(), amount, busdAmount, block.timestamp);

        // add to list of user IDs
        userIDs[_msgSender()].push(id);

        ++id;

        // update total amount
        total += amount;
        totalBUSD += busdAmount;

        // ensure allowance and balance
        require(busd.allowance(_msgSender(), address(this)) >= busdAmount, 'Insufficient Allowance');
        require(busd.balanceOf(_msgSender()) >= busdAmount, 'Insufficient Balance');

        // transfer BUSD from caller to this smart contract
        require(busd.transferFrom(_msgSender(), address(this), busdAmount), 'Error Transfer From');

        emit Deposit(_msgSender(), amount, busdAmount);
    }

    /* ==================== VIEW METHODS ==================== */

    /**
     * @dev get total deposit count of one user
     * @param owner address
     * @return count of a user's all DepositInfo
     */
    function countOf(address owner) public view returns (uint256 count) {
        return userIDs[owner].length;
    }

    /**
     * @dev get total deposit information of one user
     * @param owner address
     * @return array of DepositInfo
     */
    function depositsOf(address owner) external view returns (DepositInfo[] memory) {
        uint256 length = userIDs[owner].length;
        DepositInfo[] memory userDeposits = new DepositInfo[](length);
        for (uint256 i = 0; i < length; ) {
            userDeposits[i] = deposits[userIDs[owner][i]];
            unchecked {
                ++i;
            }
        }
        return userDeposits;
    }

    /**
     * @dev get total deposit information of one user
     * @param owner address
     * @return array of DepositInfo
     */
    function depositsOfOwnerInRange(address owner, uint startIndex, uint endIndex) external view returns (DepositInfo[] memory) {
        uint256 length = endIndex - startIndex;
        uint256 count = 0;
        DepositInfo[] memory userDeposits = new DepositInfo[](length);
        for (uint256 i = startIndex; i < endIndex; ) {
            userDeposits[count] = deposits[userIDs[owner][i]];
            unchecked {
                ++count;
                ++i;
            }
        }
        return userDeposits;
    }

    /**
     * @dev get current active merkel tree root
     */
    function getMerkleRoot() external view returns (bytes32) {
        return root;
    }

    /**
     * @dev check if user is whitelisted or not
     * @param proof new merkle tree root
     * @return bool weather whitelisted or not
     */
    function checkWhitelist(bytes32[] calldata proof) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(_msgSender()));
        return MerkleProof.verify(proof, root, leaf);
    }

    /* ==================== OWNER METHODS ==================== */

    /**
     * @dev owner can withdraw the fund to team and dev wallets
     * @param amount BUSD amount in wei
     */
    function withdraw(uint256 amount) external onlyOwner {
        _withdraw(amount);
    }

    /**
     * @dev owner can withdraw all the funds to team and dev wallets
     */
    function withdrawAll() external onlyOwner {
        _withdraw(busd.balanceOf(address(this)));
    }

    function withdrawToken(address token) external onlyOwner {
        require(token != address(busd), 'Call withdraw() for BUSD');
        require(IERC20(token).transfer(msg.sender, IERC20(token).balanceOf(address(this))), "Can't withdraw ERC20 tokens!");
    }

    /**
     * @dev owner can set the fund and dev team wallet address
     * @param _fund main team fund wallet address
     * @param _dev dev team wallet address
     */
    function setFundAddresses(address _fund, address _dev) external onlyOwner {
        if (_fund == address(0) || _dev == address(0)) revert ZeroAddress();

        fund = _fund;
        dev = _dev;
    }

    /**
     * @dev owner can set merkle tree root for whitelisted users
     * @param _root new merkle tree roots
     */
    function setRoot(bytes32 _root) external onlyOwner {
        root = _root;

        emit SetMerkleTreeRoot(_msgSender(), root);
    }

    function setDevFee(uint256 newFee) external onlyOwner {
        require(
            newFee <= 50,
            'Dev Fee Too High'
        );
        devFee = newFee;
    }
// @audit owner can change price during execution of deposit function
    function setPackagePrice(uint newPrice) external onlyOwner {
        require(newPrice > 0, 'Zero Price');
        price = newPrice;
    }

    function _withdraw(uint amount) internal {
        uint256 amountToDev = (amount * devFee) / 100;
        uint256 amountToFund = amount - amountToDev;

        if (amountToFund > 0) {
            require(busd.transfer(fund, amountToFund), "Can't transfer BUSD!");
        }
        if (amountToDev > 0) {
            require(busd.transfer(dev, amountToDev), "Can't transfer BUSD!");
        }

        emit Withdraw(fund, amountToFund, dev, amountToDev);
    }

    function airdrop(uint256 token, address[] calldata users, uint256[] calldata amounts) external onlyOwner {
        require(token != address(0), "Invalid address!");

        require(users.length == amounts.length, "Invalid parameters!");

        for(uint256 i = 0; i < amounts.length;) {
            require(IERC20(token).transferFrom(address(this), users[i], amounts[i]), "Can't send ERC20 tokens!");
            
            unchecked {
                ++i;
            }
        }
    }
}