// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/IncrementalMerkleTree.sol";

contract IncrementalMerkleTreeTest is Test {
    IncrementalMerkleTree public tree;

    event LeafAdded(uint256 indexed leaf, uint256 leafIndex, uint256 timestamp);

    function setUp() public {
        address poseidon;
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = "poseidon-bytecode.txt";
        bytes memory poseidonBytecode = vm.ffi(cmds);

        assembly {
            poseidon := create(
                0,
                add(poseidonBytecode, 0x20),
                mload(poseidonBytecode)
            )
        }
        emit log_named_address("Poseidon contract address: ", poseidon);

        tree = new IncrementalMerkleTree(5, 9, poseidon);
        emit log_named_address("Tree contract address: ", address(tree));
    }

    function testInitializedRoot() public {
        uint32 treeDepth = tree.treeDepth();
        assertEq(tree.getLastRoot(), tree.zeros(treeDepth - 1));
    }

    function testInitializedFilledSubTress() public {
        // check that subTrees are correctly initialized
        uint32 treeDepth = tree.treeDepth();
        for (uint32 i; i < treeDepth; i++) {
            assertEq(tree.filledSubTrees(i), tree.zeros(i));
        }
        // should be equal to zero, since we don't want to initialize this value with a depth of treeDepth
        assertEq(
            tree.filledSubTrees(treeDepth),
            0x0000000000000000000000000000000000000000000000000000000000000000
        );
    }

    function testFullTreeError() public {
        uint32 treeDepth = tree.treeDepth();
        for (uint32 i; i < 2**treeDepth; i++) {
            tree.addLeaf(42);
        }
        // this tx should throw the error since we already added the maximum leaves (2 ** treeDepth)
        vm.expectRevert(
            abi.encodeWithSelector(
                _getSelector("MerkleTreeIsFull(uint256,uint256)"),
                treeDepth,
                2**treeDepth
            )
        );
        tree.addLeaf(42);
    }

    function testLeafAddedEvent() public {
        // we add 2 leaves before the one we are interested about
        // in order to check that the leafIndex is correct in the event
        tree.addLeaf(12);
        tree.addLeaf(34);

        // We check that topic 1 and data is true (topic 2 and 3 are set to false)
        vm.expectEmit(true, false, false, true);
        // the evnet we expect
        emit LeafAdded(123, 2, block.timestamp);
        // the tested event with this leaf
        tree.addLeaf(123);
    }

    function _getSelector(string memory func) internal pure returns (bytes4) {
        return bytes4(keccak256(bytes(func)));
    }
}
