#ifndef OMAP_H
#define OMAP_H
#include <iostream>
#include "ORAM.hpp"
#include <functional>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <iostream>
#include "AVLTree.hpp"
using namespace std;

template <typename T>
class OMAP
{
private:
    Bid rootKey;
    unsigned long long rootPos;

public:
    AVLTree<T> *treeHandler;
    OMAP(int maxSize, bytes<Key> key)
    {
        treeHandler = new AVLTree<T>(maxSize, key, true);
        rootKey = 0;
    }

    // OMAP(int maxSize, bytes<Key> secretKey, map<Bid, vector<byte_t>> *pairs, map<unsigned long long, unsigned long long> *permutation)
    // {
    //     treeHandler = new AVLTree<T>(maxSize, secretKey, rootKey, rootPos, pairs, permutation);
    // }

    OMAP(int maxSize, Bid rootBid, long long rootPos, bytes<Key> secretKey)
    {
        treeHandler = new AVLTree<T>(maxSize, secretKey, false);
        this->rootKey = rootBid;
        this->rootPos = rootPos;
    }

    virtual ~OMAP()
    {
    }

    void insert(Bid key, vector<byte_t> value)
    {
        if (treeHandler->logTime)
        {
            treeHandler->times[0].push_back(0);
        }
        treeHandler->totheight = 0;
        int height;
        treeHandler->startOperation(false);
        if (rootKey == 0)
        {
            rootKey = treeHandler->insert(0, rootPos, key, value, height, key, false);
        }
        else
        {
            rootKey = treeHandler->insert(rootKey, rootPos, key, value, height, key, false);
        }
        double y;
        if (treeHandler->logTime)
        {
            ocall_start_timer(898);
        }
        treeHandler->finishOperation();
        if (treeHandler->logTime)
        {
            ocall_stop_timer(&y, 898);
            treeHandler->times[1].push_back(y);
        }
    }

    vector<byte_t> find(Bid key)
    {
        double y;
        if (treeHandler->logTime)
        {
            ocall_start_timer(950);
        }
        if (rootKey == 0)
        {
            return vector<byte_t>(sizeof(T), 0);
        }
        treeHandler->startOperation(false);
        Node<T> *node = new Node<T>();
        node->key = rootKey;
        node->pos = rootPos;
        vector<byte_t> res = treeHandler->search(node, key);
        rootPos = node->pos;
        delete node;
        if (treeHandler->logTime)
        {
            ocall_stop_timer(&y, 950);
            treeHandler->times[2].push_back(y);
            ocall_start_timer(950);
        }
        treeHandler->finishOperation();
        if (treeHandler->logTime)
        {
            ocall_stop_timer(&y, 950);
            treeHandler->times[3].push_back(y);
        }
        return res;
    }

    void printTree()
    {
        Node<T> *node = new Node<T>();
        node->key = rootKey;
        node->pos = rootPos;
        treeHandler->printTree(node, 0);
    }

    void batchInsert(map<Bid, vector<byte_t>> pairs)
    {
        treeHandler->startOperation(true);
        int cnt = 0, height;
        for (auto pair : pairs)
        {
            cnt++;
            if (rootKey == 0)
            {
                rootKey = treeHandler->insert(0, rootPos, pair.first, pair.second, height, 0, false);
            }
            else
            {
                rootKey = treeHandler->insert(rootKey, rootPos, pair.first, pair.second, height, 0, false);
            }
        }
        treeHandler->finishOperation();
    }

    vector<vector<byte_t>> batchSearch(vector<Bid> keys)
    {
        vector<vector<byte_t>> result;
        treeHandler->startOperation(false);
        Node<T> *node = new Node<T>();
        node->key = rootKey;
        node->pos = rootPos;

        vector<Node<T> *> resNodes;
        treeHandler->batchSearch(node, keys, &resNodes);
        for (Node<T> *n : resNodes)
        {
            vector<byte_t> res(sizeof(T), 0);
            if (n != NULL)
            {
                res.assign(n->value.begin(), n->value.end());
                result.push_back(res);
            }
            else
            {
                vector<byte_t> t(sizeof(T), 0);
                result.push_back(t);
            }
        }
        treeHandler->finishOperation();
        return result;
    }
};

#endif /* OMAP_H */
