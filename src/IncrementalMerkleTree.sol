//SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title Incremental Merkle Tree
 * @author bigq
 * @notice This contract is bigq's hiring project for Sismo
 * @dev This contract has some specifications:
 * - The depth should be fixed (using the constructor)
 * - The number of last historical roots should also be fixed (usign the constructor)
 * - The contract should have an `addLeaf(uint256 leaf)` function and emit an event when a leaf is added
 * - The merkle tree should be compatible with the https://github.com/sismo-core/sismo-utils/tree/main/packages/kv-merkle-tree
 *   and this poseidon hash function https://github.com/sismo-core/sismo-utils/blob/main/packages/crypto/src/poseidon.ts.
 *   That means a root created with N leafs using the `KVMerkleTree.fromLeaves` (instantiated with the poseidon hash function)
 *   should be the same as the one in the incremental Merkle tree contract.
 */

interface IPoseidon {
    function poseidon(bytes32[2] memory) external pure returns (bytes32);
}

contract IncrementalMerkleTree {
    // address where the Poseidon hash is implemented
    IPoseidon immutable poseidon;

    uint256 public maxNbRoots;
    uint256 public currentRootIndex;
    uint32 public treeDepth;
    uint32 public nextIndex;

    // we store only maxNbRoots historical roots
    mapping(uint256 => bytes32) public roots;
    mapping(uint256 => bytes32) public filledSubTrees;

    /**
     * @dev Event to emit each time a new leaf is added to the tree
     * @param leaf the hash of the data included in the tree
     * @param leafIndex the index of the leaf in the three
     * @param timestamp the UNIX time when the leaf was included in the tree
     */
    event LeafAdded(uint256 indexed leaf, uint256 leafIndex, uint256 timestamp);

    /**
     * @dev Error to revert when the depth inputed is not correct
     * @param inputed the wrong tree depth inputed
     */
    error IncorrectTreeDepth(uint32 inputed);

    // Error to revert when maxNbRoots is below or equal to zero
    error IncorrectMaxNbRoots();

    /**
     * @dev Error to revert when the merkle tree is full
     * @param treeDepth the depth of the tree, in order to check if nextIndex is really incorrect
     * @param nextIndex the index that is the source of the issue (too large for the tree implemented)
     */
    error MerkleTreeIsFull(uint256 treeDepth, uint256 nextIndex);

    /**
     * @dev Constructor
     * @param _treeDepth The fixed depth of the incremental Merke Tree
     * @param _maxNbRoots  The maximum number of historical roots that we can store in the roots mapping
     * @param _poseidon    Address of the contract where the poseidon hash is implemented
     */
    constructor(uint32 _treeDepth, uint256 _maxNbRoots, address _poseidon) {
        if ((_treeDepth <= 0) || (_treeDepth >= 32)) {
            revert IncorrectTreeDepth(_treeDepth);
        }
        if (_maxNbRoots <= 0) {
            revert IncorrectMaxNbRoots();
        }

        treeDepth = _treeDepth;
        maxNbRoots = _maxNbRoots;
        poseidon = IPoseidon(_poseidon);

        // populate subtrees with Zero hashes in order to compute a future correct root
        // when adding a future new leaf
        for (uint32 i = 0; i < _treeDepth; i++) {
            filledSubTrees[i] = zeros(i);
        }

        // store the first root, the tree is full of Zero leaves
        roots[0] = zeros(_treeDepth - 1);
    }

    /**
     * @dev adds a new leaf to the Merkle Tree
     * @param leaf The hash of the data we want to insert in the tree
     */
    function addLeaf(uint256 leaf) external {
        uint32 _treeDepth = treeDepth;
        uint32 _nextIndex = nextIndex;

        if (_nextIndex >= uint32(2) ** _treeDepth) {
            revert MerkleTreeIsFull(_treeDepth, _nextIndex);
        }

        uint32 currentIndex = _nextIndex;
        bytes32 currentLevelHash = bytes32(leaf);
        bytes32 left;
        bytes32 right;

        for (uint32 i = 0; i < _treeDepth; i++) {
            if (currentIndex % 2 == 0) {
                left = currentLevelHash;
                right = zeros(i);
                filledSubTrees[i] = currentLevelHash;
            } else {
                left = filledSubTrees[i];
                right = currentLevelHash;
            }
            // compute the node hash
            currentLevelHash = IPoseidon(poseidon).poseidon([left, right]);
            currentIndex /= 2;
        }

        uint256 newRootIndex = (currentRootIndex + 1) % maxNbRoots;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = currentLevelHash;
        nextIndex = _nextIndex + 1;

        emit LeafAdded(leaf, _nextIndex, block.timestamp);
    }

    /**
     * @dev returns the last root of the tree
     */
    function getLastRoot() public view returns (bytes32) {
        return roots[currentRootIndex];
    }

    /**
     * @dev provides Zero (Empty) elements for a Poseidon IncrementalMerkleTree. Up to 19 levels for now
     * This list has been taken from: https://github.com/sismo-core/sismo-utils/blob/main/packages/kv-merkle-tree/src/kv-merkle-tree.ts
     * in order to be compatible with the off-chain tree construction
     * The list of hashes has been completed with this script: https://github.com/yum0e/incremental-merkle-tree/blob/main/scripts/computeHashes.js
     */
    function zeros(uint256 i) public pure returns (bytes32) {
        if (i == 0) {
            return bytes32(0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864);
        } else if (i == 1) {
            return bytes32(0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1);
        } else if (i == 2) {
            return bytes32(0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238);
        } else if (i == 3) {
            return bytes32(0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a);
        } else if (i == 4) {
            return bytes32(0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55);
        } else if (i == 5) {
            return bytes32(0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78);
        } else if (i == 6) {
            return bytes32(0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d);
        } else if (i == 7) {
            return bytes32(0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61);
        } else if (i == 8) {
            return bytes32(0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747);
        } else if (i == 9) {
            return bytes32(0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2);
        } else if (i == 10) {
            return bytes32(0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636);
        } else if (i == 11) {
            return bytes32(0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a);
        } else if (i == 12) {
            return bytes32(0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0);
        } else if (i == 13) {
            return bytes32(0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c);
        } else if (i == 14) {
            return bytes32(0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92);
        } else if (i == 15) {
            return bytes32(0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323);
        } else if (i == 16) {
            return bytes32(0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992);
        } else if (i == 17) {
            return bytes32(0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f);
        } else if (i == 18) {
            return bytes32(0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca);
        } else if (i == 19) {
            return bytes32(0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e);
        } else if (i == 20) {
            return bytes32(0x19df90ec844ebc4ffeebd866f33859b0c051d8c958ee3aa88f8f8df3db91a5b1);
        } else if (i == 21) {
            return bytes32(0x18cca2a66b5c0787981e69aefd84852d74af0e93ef4912b4648c05f722efe52b);
        } else if (i == 22) {
            return bytes32(0x2388909415230d1b4d1304d2d54f473a628338f2efad83fadf05644549d2538d);
        } else if (i == 23) {
            return bytes32(0x27171fb4a97b6cc0e9e8f543b5294de866a2af2c9c8d0b1d96e673e4529ed540);
        } else if (i == 24) {
            return bytes32(0x2ff6650540f629fd5711a0bc74fc0d28dcb230b9392583e5f8d59696dde6ae21);
        } else if (i == 25) {
            return bytes32(0x120c58f143d491e95902f7f5277778a2e0ad5168f6add75669932630ce611518);
        } else if (i == 26) {
            return bytes32(0x1f21feb70d3f21b07bf853d5e5db03071ec495a0a565a21da2d665d279483795);
        } else if (i == 27) {
            return bytes32(0x24be905fa71335e14c638cc0f66a8623a826e768068a9e968bb1a1dde18a72d2);
        } else if (i == 28) {
            return bytes32(0x0f8666b62ed17491c50ceadead57d4cd597ef3821d65c328744c74e553dac26d);
        } else if (i == 29) {
            return bytes32(0x0918d46bf52d98b034413f4a1a1c41594e7a7a3f6ae08cb43d1a2a230e1959ef);
        } else if (i == 30) {
            return bytes32(0x1bbeb01b4c479ecde76917645e404dfa2e26f90d0afc5a65128513ad375c5ff2);
        } else if (i == 31) {
            return bytes32(0x2f68a1c58e257e42a17a6c61dff5551ed560b9922ab119d5ac8e184c9734ead9);
        } else {
            revert("Index out of bounds");
        }
    }
}
