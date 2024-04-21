#include "AVLTree.hpp"
// #include "Enclave.h"

//     AVLTree::~AVLTree()

//     // A utility function to get maximum of two integers

//     // A utility function to right rotate subtree rooted with leftNode
//     // See the diagram given above.

//     // string AVLTree::search(Node* rootNode, Bid omapKey) {
//     //     Bid curKey = rootNode->key;
//     //     unsigned long long lastPos = rootNode->pos;
//     //     unsigned long long newPos = RandomPath();
//     //     rootNode->pos = newPos;
//     //     string res = "";
//     //     Bid dumyID = oram->nextDummyCounter;
//     //     Node* tmpDummyNode = new Node();
//     //     tmpDummyNode->isDummy = true;
//     //     Node* head;
//     //     int dummyState = 0;
//     //     int upperBound = (int) (1.44 * oram->depth);
//     //     bool found = false;
//     //     unsigned long long dumyPos;
//     //     do {
//     //         head = oram->ReadWrite(curKey, tmpDummyNode, lastPos, newPos, true, dummyState > 1 ? true : false);
//     //         //        head = oram->ReadNode(curKey, lastPos, newPos, dummyState > 1 ? true : false);
//     //         unsigned long long rnd = RandomPath();
//     //         if (dummyState > 1) {
//     //             lastPos = rnd;
//     //             head->rightPos = head->rightPos;
//     //             head->leftPos = head->leftPos;
//     //             curKey = dumyID;
//     //             newPos = rnd;
//     //             res.assign(res.begin(), res.end());
//     //             dummyState = dummyState;
//     //             head->key = dumyID;
//     //             found = found;
//     //         } else if (head->key > omapKey) {
//     //             lastPos = head->leftPos;
//     //             head->rightPos = head->rightPos;
//     //             head->leftPos = rnd;
//     //             curKey = head->leftID;
//     //             newPos = head->leftPos;
//     //             res.assign(head->value.begin(), head->value.end());
//     //             dummyState = dummyState;
//     //             head->key = head->key;
//     //             found = found;
//     //         } else if (head->key < omapKey) {
//     //             lastPos = head->rightPos;
//     //             head->rightPos = rnd;
//     //             head->leftPos = head->leftPos;
//     //             curKey = head->rightID;
//     //             newPos = head->rightPos;
//     //             res.assign(head->value.begin(), head->value.end());
//     //             dummyState = dummyState;
//     //             head->key = head->key;
//     //             found = found;
//     //         } else {
//     //             lastPos = lastPos;
//     //             head->rightPos = head->rightPos;
//     //             head->leftPos = head->leftPos;
//     //             curKey = dumyID;
//     //             newPos = newPos;
//     //             res.assign(head->value.begin(), head->value.end());
//     //             dummyState = dummyState;
//     //             dummyState++;
//     //             head->key = head->key;
//     //             found = true;
//     //         }
//     //         oram->ReadWrite(head->key, head, head->pos, head->pos, false, dummyState <= 1 ? false : true);
//     //         //        oram->WriteNode(head->key, head, oram->evictBuckets, dummyState <= 1 ? false : true);
//     //         dummyState == 1 ? dummyState++ : dummyState;
//     //     } while (!found || oram->readCnt < upperBound);
//     //
//     //     return res;
//     // }

//     /**
//      * a recursive search function which traverse binary tree to find the target node
//      */

//     /*
//      * before executing each operation, this function should be called with proper arguments
//      */

//     /*
//      * after executing each operation, this function should be called with proper arguments
//      */
