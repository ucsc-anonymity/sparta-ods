#ifndef ORAM_H
#define ORAM_H

#include <array>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "AES.hpp"
#include "Bid.h"
#include "Enclave.h" /* print_string */
#include "LocalRAMStore.hpp"
#include "sgx_trts.h"

using namespace std;

template <typename T>
class Node
{
public:
    Node()
    {
    }

    Node(Bid k, vector<byte_t> v, unsigned long long p) : key(k), pos(p)
    {
        // copy the first sizeof(T) bytes over into value
        if (v.size() != sizeof(T))
        {
            throw std::invalid_argument("Invalid size for value.");
        }
        std::copy(v.begin(), v.end(), value.begin());
        isDummy = false;
    }

    ~Node()
    {
    }
    unsigned long long index;
    std::array<byte_t, sizeof(T)> value;
    Bid key;
    unsigned long long pos;
    int height;
    long long evictionNode;
    bool isDummy;
    Bid leftID;
    Bid rightID;
    bool modified;
    unsigned long long leftPos;
    unsigned long long rightPos;

    static Node *clone(Node *oldNode)
    {
        Node *newNode = new Node();
        newNode->evictionNode = oldNode->evictionNode;
        newNode->index = oldNode->index;
        newNode->key = oldNode->key;
        newNode->pos = oldNode->pos;
        newNode->rightID = oldNode->rightID;
        newNode->leftID = oldNode->leftID;
        newNode->value = oldNode->value;
        newNode->isDummy = oldNode->isDummy;
        newNode->modified = oldNode->modified;
        newNode->leftPos = oldNode->leftPos;
        newNode->height = oldNode->height;
        newNode->rightPos = oldNode->rightPos;
        return newNode;
    }

    /**
     * constant time comparator
     * @param left
     * @param right
     * @return left < right -> -1,  left = right -> 0, left > right -> 1
     */
    static int CTcmp(long long lhs, long long rhs)
    {
        unsigned __int128 overflowing_iff_lt = (__int128)lhs - (__int128)rhs;
        unsigned __int128 overflowing_iff_gt = (__int128)rhs - (__int128)lhs;
        int is_less_than = (int)-(overflowing_iff_lt >> 127);   // -1 if self < other, 0 otherwise.
        int is_greater_than = (int)(overflowing_iff_gt >> 127); // 1 if self > other, 0 otherwise.
        int result = is_less_than + is_greater_than;
        return result;
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static long long conditional_select(long long a, long long b, int choice)
    {
        unsigned long long one = 1;
        return (~((unsigned long long)choice - one) & a) | ((unsigned long long)(choice - one) & b);
    }

    static unsigned long long conditional_select(unsigned long long a, unsigned long long b, int choice)
    {
        unsigned long long one = 1;
        return (~((unsigned long long)choice - one) & a) | ((unsigned long long)(choice - one) & b);
    }

    static unsigned int conditional_select(unsigned int a, unsigned int b, int choice)
    {
        unsigned int one = 1;
        return (~((unsigned int)choice - one) & a) | ((unsigned int)(choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static unsigned __int128 conditional_select(unsigned __int128 a, unsigned __int128 b, int choice)
    {
        unsigned __int128 one = 1;
        return (~((unsigned __int128)choice - one) & a) | ((unsigned __int128)(choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static byte_t conditional_select(byte_t a, byte_t b, int choice)
    {
        byte_t one = 1;
        return (~((byte_t)choice - one) & a) | ((byte_t)(choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> b->a , choice = 0 -> return a->a
     */
    static void conditional_assign(Node *a, Node *b, int choice)
    {
        a->index = Node::conditional_select((long long)b->index, (long long)a->index, choice);
        a->isDummy = Node::conditional_select(b->isDummy, a->isDummy, choice);
        a->pos = Node::conditional_select((long long)b->pos, (long long)a->pos, choice);
        for (int k = 0; k < b->value.size(); k++)
        {
            a->value[k] = Node::conditional_select(b->value[k], a->value[k], choice);
        }
        a->evictionNode = Node::conditional_select(b->evictionNode, a->evictionNode, choice);
        a->modified = Node::conditional_select(b->modified, a->modified, choice);
        a->height = Node::conditional_select(b->height, a->height, choice);
        a->leftPos = Node::conditional_select(b->leftPos, a->leftPos, choice);
        a->rightPos = Node::conditional_select(b->rightPos, a->rightPos, choice);
        for (int k = 0; k < a->key.id.size(); k++)
        {
            a->key.id[k] = Node::conditional_select(b->key.id[k], a->key.id[k], choice);
        }
        for (int k = 0; k < a->leftID.id.size(); k++)
        {
            a->leftID.id[k] = Node::conditional_select(b->leftID.id[k], a->leftID.id[k], choice);
        }
        for (int k = 0; k < a->rightID.id.size(); k++)
        {
            a->rightID.id[k] = Node::conditional_select(b->rightID.id[k], a->rightID.id[k], choice);
        }
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static void conditional_swap(Node *a, Node *b, int choice)
    {
        Node tmp = *b;
        b->index = Node::conditional_select((long long)a->index, (long long)b->index, choice);
        b->isDummy = Node::conditional_select(a->isDummy, b->isDummy, choice);
        b->pos = Node::conditional_select((long long)a->pos, (long long)b->pos, choice);
        for (int k = 0; k < b->value.size(); k++)
        {
            b->value[k] = Node::conditional_select(a->value[k], b->value[k], choice);
        }
        b->evictionNode = Node::conditional_select(a->evictionNode, b->evictionNode, choice);
        b->modified = Node::conditional_select(a->modified, b->modified, choice);
        b->height = Node::conditional_select(a->height, b->height, choice);
        b->leftPos = Node::conditional_select(a->leftPos, b->leftPos, choice);
        b->rightPos = Node::conditional_select(a->rightPos, b->rightPos, choice);
        for (int k = 0; k < b->key.id.size(); k++)
        {
            b->key.id[k] = Node::conditional_select(a->key.id[k], b->key.id[k], choice);
        }
        for (int k = 0; k < b->leftID.id.size(); k++)
        {
            b->leftID.id[k] = Node::conditional_select(a->leftID.id[k], b->leftID.id[k], choice);
        }
        for (int k = 0; k < b->rightID.id.size(); k++)
        {
            b->rightID.id[k] = Node::conditional_select(a->rightID.id[k], b->rightID.id[k], choice);
        }

        a->index = Node::conditional_select((long long)tmp.index, (long long)a->index, choice);
        a->isDummy = Node::conditional_select(tmp.isDummy, a->isDummy, choice);
        a->pos = Node::conditional_select((long long)tmp.pos, (long long)a->pos, choice);
        for (int k = 0; k < b->value.size(); k++)
        {
            a->value[k] = Node::conditional_select(tmp.value[k], a->value[k], choice);
        }
        a->evictionNode = Node::conditional_select(tmp.evictionNode, a->evictionNode, choice);
        a->modified = Node::conditional_select(tmp.modified, a->modified, choice);
        a->height = Node::conditional_select(tmp.height, a->height, choice);
        a->leftPos = Node::conditional_select(tmp.leftPos, a->leftPos, choice);
        a->rightPos = Node::conditional_select(tmp.rightPos, a->rightPos, choice);
        for (int k = 0; k < a->key.id.size(); k++)
        {
            a->key.id[k] = Node::conditional_select(tmp.key.id[k], a->key.id[k], choice);
        }
        for (int k = 0; k < a->leftID.id.size(); k++)
        {
            a->leftID.id[k] = Node::conditional_select(tmp.leftID.id[k], a->leftID.id[k], choice);
        }
        for (int k = 0; k < a->rightID.id.size(); k++)
        {
            a->rightID.id[k] = Node::conditional_select(tmp.rightID.id[k], a->rightID.id[k], choice);
        }
    }

    static void conditional_swap(unsigned long long &a, unsigned long long &b, int choice)
    {
        unsigned long long tmp = b;
        b = Node::conditional_select((long long)a, (long long)b, choice);
        a = Node::conditional_select((long long)tmp, (long long)a, choice);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static int conditional_select(int a, int b, int choice)
    {
        unsigned int one = 1;
        return (~((unsigned int)choice - one) & a) | ((unsigned int)(choice - one) & b);
    }

    static bool CTeq(int a, int b)
    {
        return !(a ^ b);
    }

    static bool CTeq(long long a, long long b)
    {
        return !(a ^ b);
    }

    static bool CTeq(unsigned __int128 a, unsigned __int128 b)
    {
        return !(a ^ b);
    }

    static bool CTeq(unsigned long long a, unsigned long long b)
    {
        return !(a ^ b);
    }
};

template <typename T>
class ObliviousOperations
{
private:
    static void bitonic_sort(vector<Node<T> *> *nodes, int low, int n, int dir)
    {
        if (n > 1)
        {
            int middle = n / 2;
            bitonic_sort(nodes, low, middle, !dir);
            bitonic_sort(nodes, low + middle, n - middle, dir);
            bitonic_merge(nodes, low, n, dir);
        }
    }

    static void bitonic_merge(vector<Node<T> *> *nodes, int low, int n, int dir)
    {
        if (n > 1)
        {
            int m = greatest_power_of_two_less_than(n);

            for (int i = low; i < (low + n - m); i++)
            {
                if (i != (i + m))
                {
                    compare_and_swap((*nodes)[i], (*nodes)[i + m], dir);
                }
            }

            bitonic_merge(nodes, low, m, dir);
            bitonic_merge(nodes, low + m, n - m, dir);
        }
    }
    static void compare_and_swap(Node<T> *item_i, Node<T> *item_j, int dir)
    {
        int res = Node<T>::CTcmp(item_i->evictionNode, item_j->evictionNode);
        int cmp = Node<T>::CTeq(res, 1);
        Node<T>::conditional_swap(item_i, item_j, Node<T>::CTeq(cmp, dir));
    }
    static int greatest_power_of_two_less_than(int n)
    {
        int k = 1;
        while (k > 0 && k < n)
        {
            k = k << 1;
        }
        return k >> 1;
    }

public:
    static long long INF;
    ObliviousOperations()
    {
    }

    virtual ~ObliviousOperations()
    {
    }

    static void oblixmergesort(std::vector<Node<T> *> *data)
    {
        if (data->size() == 0 || data->size() == 1)
        {
            return;
        }
        int len = data->size();
        int t = ceil(log2(len));
        long long p = 1 << (t - 1);

        while (p > 0)
        {
            long long q = 1 << (t - 1);
            long long r = 0;
            long long d = p;

            while (d > 0)
            {
                long long i = 0;
                while (i < len - d)
                {
                    if ((i & p) == r)
                    {
                        long long j = i + d;
                        if (i != j)
                        {
                            int node_cmp = Node<T>::CTcmp((*data)[j]->evictionNode, (*data)[i]->evictionNode);
                            int dummy_blocks_last = Node<T>::CTcmp((*data)[i]->isDummy, (*data)[j]->isDummy);
                            int same_nodes = Node<T>::CTeq(node_cmp, 0);
                            bool cond = Node<T>::CTeq(Node<T>::conditional_select(dummy_blocks_last, node_cmp, same_nodes), -1);
                            Node<T>::conditional_swap((*data)[i], (*data)[j], cond);
                        }
                    }
                    i += 1;
                }
                d = q - p;
                q /= 2;
                r = p;
            }
            p /= 2;
        }
        std::reverse(data->begin(), data->end());
    }

    static void bitonicSort(vector<Node<T> *> *nodes)
    {
        int len = nodes->size();
        bitonic_sort(nodes, 0, len, 1);
    }
};

extern int BlockValueSize;
extern int BlockDummySize;

struct Block
{
    unsigned long long id;
    block data;
};

using Bucket = std::array<Block, Z>;

template <typename T>
class Cache
{
public:
    vector<Node<T> *> nodes;

    void preAllocate(int n)
    {
        nodes.reserve(n);
    }

    void insert(Node<T> *node)
    {
        nodes.push_back(node);
    };
};

template <typename T>
class ORAM
{
private:
    unsigned long long INF;
    unsigned int PERMANENT_STASH_SIZE;

    bool map;
    size_t blockSize;
    unordered_map<long long, Bucket> virtualStorage;
    Cache<T> stash, incStash;
    unsigned long long currentLeaf;

    bytes<Key> key;
    size_t plaintext_size;
    long long bucketCount;
    size_t clen_size;
    bool batchWrite = false;
    long long maxOfRandom;
    long long maxHeightOfAVLTree;
    bool useLocalRamStore = false;
    LocalRAMStore *localStore;
    int storeBlockSize;
    int stashCounter = 0;
    bool isIncomepleteRead = false;

    long long GetNodeOnPath(long long leaf, int curDepth)
    {
        leaf += bucketCount / 2;
        for (int d = depth - 1; d >= 0; d--)
        {
            bool cond = !Node<T>::CTeq(Node<T>::CTcmp(d, curDepth), -1);
            leaf = Node<T>::conditional_select((leaf + 1) / 2 - 1, leaf, cond);
        }
        return leaf;
    }

    void WriteBucket(long long index, Bucket bucket)
    {
        block b = SerialiseBucket(bucket);
        block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
        if (!useLocalRamStore)
        {
            ocall_write_ramStore(map, index, (const char *)ciphertext.data(), (size_t)ciphertext.size());
        }
        else
        {
            localStore->Write(index, ciphertext);
        }
    }

    void FetchPath(long long leaf)
    {
        readCnt++;
        vector<long long> nodesIndex;
        vector<long long> existingIndexes;

        long long node = leaf;

        node += bucketCount / 2;
        if (virtualStorage.count(node) == 0)
        {
            nodesIndex.push_back(node);
        }
        else
        {
            existingIndexes.push_back(node);
        }

        for (int d = depth - 1; d >= 0; d--)
        {
            node = (node + 1) / 2 - 1;
            if (virtualStorage.count(node) == 0)
            {
                nodesIndex.push_back(node);
            }
            else
            {
                existingIndexes.push_back(node);
            }
        }

        ReadBuckets(nodesIndex);

        for (unsigned int i = 0; i < existingIndexes.size(); i++)
        {
            Bucket bucket = virtualStorage[existingIndexes[i]];
            for (int z = 0; z < Z; z++)
            {
                Block &curBlock = bucket[z];
                Node<T> *node = convertBlockToNode(curBlock.data);
                bool cond = Node<T>::CTeq(node->index, (unsigned long long)0);
                node->index = Node<T>::conditional_select(node->index, nextDummyCounter, !cond);
                node->isDummy = Node<T>::conditional_select(0, 1, !cond);
                if (isIncomepleteRead)
                {
                    incStash.insert(node);
                }
                else
                {
                    stash.insert(node);
                }
            }
        }
    }

    block SerialiseBucket(Bucket bucket)
    {
        block buffer;
        for (int z = 0; z < Z; z++)
        {
            Block b = bucket[z];
            buffer.insert(buffer.end(), b.data.begin(), b.data.end());
        }
        assert(buffer.size() == Z * (blockSize));
        return buffer;
    }

    Bucket DeserialiseBucket(block buffer)
    {
        assert(buffer.size() == Z * (blockSize));
        Bucket bucket;
        for (int z = 0; z < Z; z++)
        {
            Block &curBlock = bucket[z];
            curBlock.data.assign(buffer.begin(), buffer.begin() + blockSize);
            Node<T> *node = convertBlockToNode(curBlock.data);
            bool cond = Node<T>::CTeq(node->index, (unsigned long long)0);
            node->index = Node<T>::conditional_select(node->index, nextDummyCounter, !cond);
            node->isDummy = Node<T>::conditional_select(0, 1, !cond);
            if (isIncomepleteRead)
            {
                incStash.insert(node);
            }
            else
            {
                stash.insert(node);
            }
            buffer.erase(buffer.begin(), buffer.begin() + blockSize);
        }
        return bucket;
    }

    void InitializeBuckets(long long strtindex, long long endindex, Bucket bucket)
    {
        block b = SerialiseBucket(bucket);
        block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
        if (useLocalRamStore)
        {
            for (long long i = strtindex; i < endindex; i++)
            {
                localStore->Write(i, ciphertext);
            }
        }
        else
        {
            ocall_initialize_ramStore(map, strtindex, endindex, (const char *)ciphertext.data(), (size_t)ciphertext.size());
        }
    }

    void ReadBuckets(vector<long long> indexes)
    {
        if (indexes.size() == 0)
        {
            return;
        }
        if (useLocalRamStore)
        {
            for (unsigned int i = 0; i < indexes.size(); i++)
            {
                block ciphertext = localStore->Read(indexes[i]);
                block buffer = AES::Decrypt(key, ciphertext, clen_size);
                Bucket bucket = DeserialiseBucket(buffer);
            }
        }
        else
        {
            size_t readSize;
            char *tmp = new char[indexes.size() * storeBlockSize];
            ocall_nread_ramStore(&readSize, map, indexes.size(), indexes.data(), tmp, indexes.size() * storeBlockSize);
            for (unsigned int i = 0; i < indexes.size(); i++)
            {
                block ciphertext(tmp + i * readSize, tmp + (i + 1) * readSize);
                block buffer = AES::Decrypt(key, ciphertext, clen_size);
                Bucket bucket = DeserialiseBucket(buffer);
                virtualStorage[indexes[i]] = bucket;
            }
            delete[] tmp;
        }
    }

    void EvictBuckets()
    {
        unordered_map<long long, Bucket>::iterator it = virtualStorage.begin();
        if (useLocalRamStore)
        {
            for (auto item : virtualStorage)
            {
                block b = SerialiseBucket(item.second);
                block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
                localStore->Write(item.first, ciphertext);
            }
        }
        else
        {
            for (unsigned int j = 0; j <= virtualStorage.size() / 10000; j++)
            {
                char *tmp = new char[10000 * storeBlockSize];
                vector<long long> indexes;
                size_t cipherSize = 0;
                for (int i = 0; i < min((int)(virtualStorage.size() - j * 10000), 10000); i++)
                {
                    block b = SerialiseBucket(it->second);
                    indexes.push_back(it->first);
                    block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
                    std::memcpy(tmp + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
                    cipherSize = ciphertext.size();
                    it++;
                }
                if (min((int)(virtualStorage.size() - j * 10000), 10000) != 0)
                {
                    ocall_nwrite_ramStore(map, min((int)(virtualStorage.size() - j * 10000), 10000), indexes.data(), (const char *)tmp, cipherSize * min((int)(virtualStorage.size() - j * 10000), 10000));
                }
                delete tmp;
                indexes.clear();
            }
        }
        virtualStorage.clear();
    }

    void WriteBuckets(vector<long long> indexes, vector<Bucket> buckets)
    {
        for (unsigned int i = 0; i < indexes.size(); i++)
        {
            if (virtualStorage.count(indexes[i]) != 0)
            {
                virtualStorage.erase(indexes[i]);
            }
            virtualStorage[indexes[i]] = buckets[i];
        }
    }

    bool WasSerialised();

    Node<T> *convertBlockToNode(block b)
    {
        Node<T> *node = new Node<T>();
        std::array<byte_t, sizeof(Node<T>)> arr;
        std::copy(b.begin(), b.begin() + sizeof(Node<T>), arr.begin());
        from_bytes(arr, *node);
        return node;
    }

    block convertNodeToBlock(Node<T> *node)
    {
        std::array<byte_t, sizeof(Node<T>)> data = to_bytes(*node);
        block b(data.begin(), data.end());
        return b;
    }

    void beginOperation()
    {
    }

public:
    unsigned long long RandomPath()
    {
        uint32_t val;
        sgx_read_rand((unsigned char *)&val, 4);
        return val % (maxOfRandom);
    }
    ORAM(bool m, long long maxSize, bytes<Key> oram_key, bool simulation, bool isEmptyMap) : key(oram_key), map(m)
    {
        depth = (int)(ceil(log2(maxSize)) - 1) + 1;
        maxOfRandom = (long long)(pow(2, depth));
        AES::Setup();
        bucketCount = maxOfRandom * 2 - 1;
        INF = 9223372036854775807 - (bucketCount);
        PERMANENT_STASH_SIZE = 90;
        stash.preAllocate(PERMANENT_STASH_SIZE * 4);
        printf("Number of leaves:%lld\n", maxOfRandom);
        printf("depth:%lld\n", depth);

        nextDummyCounter = INF;
        blockSize = sizeof(Node<T>); // B
        printf("block size is:%d\n", blockSize);
        size_t blockCount = (size_t)(Z * bucketCount);
        storeBlockSize = (size_t)(IV + AES::GetCiphertextLength((int)(Z * (blockSize))));
        clen_size = AES::GetCiphertextLength((int)(blockSize)*Z);
        plaintext_size = (blockSize)*Z;
        if (!simulation)
        {
            if (useLocalRamStore)
            {
                localStore = new LocalRAMStore(blockCount, storeBlockSize);
            }
            else
            {
                ocall_setup_ramStore(map, blockCount, storeBlockSize);
            }
        }
        else
        {
            ocall_setup_ramStore(map, depth, -1);
        }

        maxHeightOfAVLTree = (int)floor(log2(blockCount)) + 1;

        printf("Initializing ORAM Buckets\n");
        Bucket bucket;
        for (int z = 0; z < Z; z++)
        {
            bucket[z].id = 0;
            bucket[z].data.resize(blockSize, 0);
        }
        if (!simulation && isEmptyMap)
        {
            InitializeORAMBuckets();
        }
        for (auto i = 0; i < PERMANENT_STASH_SIZE; i++)
        {
            Node<T> *dummy = new Node<T>();
            dummy->index = nextDummyCounter;
            dummy->evictionNode = -1;
            dummy->isDummy = true;
            dummy->leftID = 0;
            dummy->leftPos = 0;
            dummy->rightPos = 0;
            dummy->rightID = 0;
            dummy->pos = 0;
            dummy->height = 1;
            stash.insert(dummy);
            nextDummyCounter++;
        }
        printf("End of Initialization\n");
    }

    void InitializeORAMBuckets()
    {
        double time;
        ocall_start_timer(687);

        //        InitializeBuckets(0, bucketCount, bucket);
        InitializeBucketsOneByOne();

        ocall_stop_timer(&time, 687);
        printf("ORAM Initialization Time:%f\n", time);
    }

    void InitializeBucketsOneByOne()
    {
        for (long long i = 0; i < bucketCount; i++)
        {
            if (i % 10000 == 0)
            {
                printf("%d/%d\n", i, bucketCount);
            }
            Bucket bucket;
            for (int z = 0; z < Z; z++)
            {
                bucket[z].id = 0;
                bucket[z].data.resize(blockSize, 0);
            }
            WriteBucket((int)i, bucket);
        }
    }

    // ORAM(long long maxSize, bytes<Key> oram_key, vector<Node<T> *> *nodes) : key(oram_key)
    // {
    //     depth = (int)(ceil(log2(maxSize)) - 1) + 1;
    //     maxOfRandom = (long long)(pow(2, depth));
    //     AES::Setup();
    //     bucketCount = maxOfRandom * 2 - 1;
    //     INF = 9223372036854775807 - (bucketCount);
    //     PERMANENT_STASH_SIZE = 90;
    //     stash.preAllocate(PERMANENT_STASH_SIZE * 4);
    //     printf("Number of leaves:%lld\n", maxOfRandom);
    //     printf("depth:%lld\n", depth);

    //     nextDummyCounter = INF;
    //     blockSize = sizeof(Node<T>); // B
    //     printf("block size is:%d\n", blockSize);
    //     size_t blockCount = (size_t)(Z * bucketCount);
    //     storeBlockSize = (size_t)(IV + AES::GetCiphertextLength((int)(Z * (blockSize))));
    //     clen_size = AES::GetCiphertextLength((int)(blockSize)*Z);
    //     plaintext_size = (blockSize)*Z;
    //     ocall_setup_ramStore(blockCount, storeBlockSize);
    //     maxHeightOfAVLTree = (int)floor(log2(blockCount)) + 1;

    //     unsigned long long first_leaf = bucketCount / 2;

    //     unsigned int j = 0;
    //     Bucket *bucket = new Bucket();

    //     int i;
    //     printf("Setting Nodes Eviction ID\n");
    //     for (i = 0; i < nodes->size(); i++)
    //     {
    //         (*nodes)[i]->evictionNode = (*nodes)[i]->pos + first_leaf;
    //     }

    //     printf("Sorting\n");
    //     ObliviousOperations<T>::bitonicSort(nodes);

    //     vector<long long> indexes;
    //     vector<Bucket> buckets;

    //     long long first_bucket_of_last_level = bucketCount / 2;

    //     for (unsigned int i = 0; i < nodes->size(); i++)
    //     {
    //         if (i % 100000 == 0)
    //         {
    //             printf("Creating Buckets:%d/%d\n", i, nodes->size());
    //         }
    //         Node<T> *cureNode = (*nodes)[i];
    //         long long curBucketID = (*nodes)[i]->evictionNode;

    //         Block &curBlock = (*bucket)[j];
    //         curBlock.data.resize(blockSize, 0);
    //         block tmp = convertNodeToBlock(cureNode);
    //         curBlock.id = Node<T>::conditional_select((unsigned long long)0, cureNode->index, cureNode->isDummy);
    //         for (int k = 0; k < tmp.size(); k++)
    //         {
    //             curBlock.data[k] = Node<T>::conditional_select(curBlock.data[k], tmp[k], cureNode->isDummy);
    //         }
    //         delete cureNode;
    //         j++;

    //         if (j == Z)
    //         {
    //             indexes.push_back(curBucketID);
    //             buckets.push_back((*bucket));
    //             delete bucket;
    //             bucket = new Bucket();
    //             j = 0;
    //         }
    //     }

    //     for (unsigned int j = 0; j <= indexes.size() / 10000; j++)
    //     {
    //         char *tmp = new char[10000 * storeBlockSize];
    //         size_t cipherSize = 0;
    //         for (int i = 0; i < min((int)(indexes.size() - j * 10000), 10000); i++)
    //         {
    //             block b = SerialiseBucket(buckets[j * 10000 + i]);
    //             block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
    //             std::memcpy(tmp + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
    //             cipherSize = ciphertext.size();
    //         }
    //         if (min((int)(indexes.size() - j * 10000), 10000) != 0)
    //         {
    //             ocall_nwrite_ramStore(min((int)(indexes.size() - j * 10000), 10000), indexes.data() + j * 10000, (const char *)tmp, cipherSize * min((int)(indexes.size() - j * 10000), 10000));
    //         }
    //         delete tmp;
    //     }

    //     indexes.clear();
    //     buckets.clear();

    //     for (int i = 0; i < first_bucket_of_last_level; i++)
    //     {
    //         if (i % 100000 == 0)
    //         {
    //             printf("Adding Upper Levels Dummy Buckets:%d/%d\n", i, nodes->size());
    //         }
    //         for (int z = 0; z < Z; z++)
    //         {
    //             Block &curBlock = (*bucket)[z];
    //             curBlock.id = 0;
    //             curBlock.data.resize(blockSize, 0);
    //         }
    //         indexes.push_back(i);
    //         buckets.push_back((*bucket));
    //         delete bucket;
    //         bucket = new Bucket();
    //     }

    //     for (unsigned int j = 0; j <= indexes.size() / 10000; j++)
    //     {
    //         char *tmp = new char[10000 * storeBlockSize];
    //         size_t cipherSize = 0;
    //         for (int i = 0; i < min((int)(indexes.size() - j * 10000), 10000); i++)
    //         {
    //             block b = SerialiseBucket(buckets[j * 10000 + i]);
    //             block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
    //             std::memcpy(tmp + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
    //             cipherSize = ciphertext.size();
    //         }
    //         if (min((int)(indexes.size() - j * 10000), 10000) != 0)
    //         {
    //             ocall_nwrite_ramStore(min((int)(indexes.size() - j * 10000), 10000), indexes.data() + j * 10000, (const char *)tmp, cipherSize * min((int)(indexes.size() - j * 10000), 10000));
    //         }
    //         delete tmp;
    //     }

    //     delete bucket;

    //     for (int i = 0; i < PERMANENT_STASH_SIZE; i++)
    //     {
    //         Node<T> *tmp = new Node<T>();
    //         tmp->index = nextDummyCounter;
    //         tmp->isDummy = true;
    //         stash.insert(tmp);
    //     }
    // }

    // ORAM(long long maxSize, bytes<Key> oram_key, vector<Node<T> *> *nodes, map<unsigned long long, unsigned long long> permutation) : key(oram_key)
    // {
    //     depth = (int)(ceil(log2(maxSize)) - 1) + 1;
    //     maxOfRandom = (long long)(pow(2, depth));
    //     AES::Setup();
    //     bucketCount = maxOfRandom * 2 - 1;
    //     INF = 9223372036854775807 - (bucketCount);
    //     PERMANENT_STASH_SIZE = 90;
    //     stash.preAllocate(PERMANENT_STASH_SIZE * 4);
    //     printf("Number of leaves:%lld\n", maxOfRandom);
    //     printf("depth:%lld\n", depth);

    //     nextDummyCounter = INF;
    //     blockSize = sizeof(Node<T>); // B
    //     printf("block size is:%d\n", blockSize);
    //     size_t blockCount = (size_t)(Z * bucketCount);
    //     storeBlockSize = (size_t)(IV + AES::GetCiphertextLength((int)(Z * (blockSize))));
    //     clen_size = AES::GetCiphertextLength((int)(blockSize)*Z);
    //     plaintext_size = (blockSize)*Z;
    //     ocall_setup_ramStore(blockCount, storeBlockSize);
    //     maxHeightOfAVLTree = (int)floor(log2(blockCount)) + 1;

    //     unsigned long long first_leaf = bucketCount / 2;

    //     unsigned int j = 0;
    //     Bucket *bucket = new Bucket();

    //     int i;
    //     printf("Setting Nodes Positions\n");
    //     for (i = 0; i < nodes->size(); i++)
    //     {
    //         (*nodes)[i]->pos = permutation[i];
    //         (*nodes)[i]->evictionNode = first_leaf + (*nodes)[i]->pos;
    //     }
    //     printf("Adding Dummy Nodes\n");
    //     unsigned long long neededDummy = ((bucketCount / 2) * Z);
    //     for (; i < neededDummy; i++)
    //     {
    //         Node<T> *tmp = new Node<T>();
    //         tmp->index = i + 1;
    //         tmp->isDummy = true;
    //         tmp->pos = permutation[i];
    //         tmp->evictionNode = permutation[i] + first_leaf;
    //         nodes->push_back(tmp);
    //     }

    //     permutation.clear();

    //     printf("Sorting\n");
    //     ObliviousOperations<T>::bitonicSort(nodes);

    //     vector<long long> indexes;
    //     vector<Bucket> buckets;

    //     long long first_bucket_of_last_level = bucketCount / 2;

    //     for (int i = 0; i < first_bucket_of_last_level; i++)
    //     {
    //         if (i % 100000 == 0)
    //         {
    //             printf("Adding Upper Levels Dummy Buckets:%d/%d\n", i, nodes->size());
    //         }
    //         for (int z = 0; z < Z; z++)
    //         {
    //             Block &curBlock = (*bucket)[z];
    //             curBlock.id = 0;
    //             curBlock.data.resize(blockSize, 0);
    //         }
    //         indexes.push_back(i);
    //         buckets.push_back((*bucket));
    //         delete bucket;
    //         bucket = new Bucket();
    //     }

    //     for (unsigned int i = 0; i < nodes->size(); i++)
    //     {
    //         if (i % 100000 == 0)
    //         {
    //             printf("Creating Buckets:%d/%d\n", i, nodes->size());
    //         }
    //         Node<T> *cureNode = (*nodes)[i];
    //         long long curBucketID = (*nodes)[i]->evictionNode;

    //         Block &curBlock = (*bucket)[j];
    //         curBlock.data.resize(blockSize, 0);
    //         block tmp = convertNodeToBlock(cureNode);
    //         curBlock.id = Node<T>::conditional_select((unsigned long long)0, cureNode->index, cureNode->isDummy);
    //         for (int k = 0; k < tmp.size(); k++)
    //         {
    //             curBlock.data[k] = Node<T>::conditional_select(curBlock.data[k], tmp[k], cureNode->isDummy);
    //         }
    //         delete cureNode;
    //         j++;

    //         if (j == Z)
    //         {
    //             indexes.push_back(curBucketID);
    //             buckets.push_back((*bucket));
    //             delete bucket;
    //             bucket = new Bucket();
    //             j = 0;
    //         }
    //     }

    //     delete bucket;

    //     for (unsigned int j = 0; j <= indexes.size() / 10000; j++)
    //     {
    //         char *tmp = new char[10000 * storeBlockSize];
    //         size_t cipherSize = 0;
    //         for (int i = 0; i < min((int)(indexes.size() - j * 10000), 10000); i++)
    //         {
    //             block b = SerialiseBucket(buckets[j * 10000 + i]);
    //             block ciphertext = AES::Encrypt(key, b, clen_size, plaintext_size);
    //             std::memcpy(tmp + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
    //             cipherSize = ciphertext.size();
    //         }
    //         if (min((int)(indexes.size() - j * 10000), 10000) != 0)
    //         {
    //             ocall_nwrite_ramStore(min((int)(indexes.size() - j * 10000), 10000), indexes.data() + j * 10000, (const char *)tmp, cipherSize * min((int)(indexes.size() - j * 10000), 10000));
    //         }
    //         delete tmp;
    //     }

    //     for (int i = 0; i < PERMANENT_STASH_SIZE; i++)
    //     {
    //         Node<T> *tmp = new Node<T>();
    //         tmp->index = nextDummyCounter;
    //         tmp->isDummy = true;
    //         stash.insert(tmp);
    //     }
    // }

    ~ORAM()
    {
        AES::Cleanup();
    }
    double evicttime = 0;
    int evictcount = 0;
    unsigned long long nextDummyCounter;
    int readCnt = 0;
    int depth;
    int accessCounter = 0;
    //-----------------------------------------------------------
    bool evictBuckets = false; // is used for AVL calls. It should be set the same as values in default values
    //-----------------------------------------------------------

    // If this is not a dummy, then we read bid stored on lastlast leaf into the
    // stash. We then clone the input and set its position to be the newleaf
    // (for writing back...), Then we create a new node to be the destination of
    // finding the correct block. We then come through the stash

    // On read I copy the node from the stash to my res. On write I copy the input to a new dummy node.
    Node<T> *ReadWrite(Bid bid, Node<T> *inputnode, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, bool isIncRead)
    {
        if (bid == 0)
        {
            printf("bid is 0 dummy is:%d\n", isDummy ? 1 : 0);
            throw runtime_error("Node id is not set");
        }
        accessCounter++;

        isIncomepleteRead = isIncRead;

        unsigned long long newPos = RandomPath();
        unsigned long long fetchPos = Node<T>::conditional_select(newPos, lastLeaf, isDummy);

        inputnode->pos = fetchPos;

        FetchPath(fetchPos);

        if (!isIncomepleteRead)
        {
            currentLeaf = fetchPos;
        }

        Node<T> *tmpWrite = Node<T>::clone(inputnode);
        tmpWrite->pos = newLeaf;

        Node<T> *res = new Node<T>();
        res->isDummy = true;
        res->index = nextDummyCounter++;
        res->key = nextDummyCounter++;
        bool write = !isRead;

        vector<Node<T> *> nodesList(stash.nodes.begin(), stash.nodes.end());

        if (isIncomepleteRead)
        {
            nodesList.insert(nodesList.end(), incStash.nodes.begin(), incStash.nodes.end());
        }

        for (Node<T> *node : nodesList)
        {
            bool match = Node<T>::CTeq(Bid::CTcmp(node->key, bid), 0) && !node->isDummy;
            node->isDummy = Node<T>::conditional_select(true, node->isDummy, !isDummy && match && write);
            node->pos = Node<T>::conditional_select(newLeaf, node->pos, !isDummy && match);
            bool choice = !isDummy && match && isRead && !node->isDummy;
            res->index = Node<T>::conditional_select((long long)node->index, (long long)res->index, choice);
            res->isDummy = Node<T>::conditional_select(node->isDummy, res->isDummy, choice);
            res->pos = Node<T>::conditional_select((long long)node->pos, (long long)res->pos, choice);
            for (int k = 0; k < res->value.size(); k++)
            {
                res->value[k] = Node<T>::conditional_select(node->value[k], res->value[k], choice);
            }
            res->evictionNode = Node<T>::conditional_select(node->evictionNode, res->evictionNode, choice);
            res->height = Node<T>::conditional_select(node->height, res->height, choice);
            res->leftPos = Node<T>::conditional_select(node->leftPos, res->leftPos, choice);
            res->rightPos = Node<T>::conditional_select(node->rightPos, res->rightPos, choice);
            for (int k = 0; k < res->key.id.size(); k++)
            {
                res->key.id[k] = Node<T>::conditional_select(node->key.id[k], res->key.id[k], choice);
            }
            for (int k = 0; k < res->leftID.id.size(); k++)
            {
                res->leftID.id[k] = Node<T>::conditional_select(node->leftID.id[k], res->leftID.id[k], choice);
            }
            for (int k = 0; k < res->rightID.id.size(); k++)
            {
                res->rightID.id[k] = Node<T>::conditional_select(node->rightID.id[k], res->rightID.id[k], choice);
            }
        }

        if (!isIncomepleteRead)
        {
            stash.insert(tmpWrite);
        }
        else
        {
            incStash.insert(tmpWrite);
        }

        if (!isIncomepleteRead)
        {
            evict(evictBuckets);
        }
        else
        {
            for (Node<T> *item : incStash.nodes)
            {
                delete item;
            }
            incStash.nodes.clear();
        }

        isIncomepleteRead = false;

        return res;
    }

    Node<T> *ReadWriteTest(Bid bid, Node<T> *inputnode, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, bool isIncRead)
    {
        if (bid == 0)
        {
            printf("bid is 0 dummy is:%d\n", isDummy ? 1 : 0);
            throw runtime_error("Node id is not set");
        }
        accessCounter++;

        isIncomepleteRead = isIncRead;

        unsigned long long newPos;
        unsigned long long fetchPos = Node<T>::conditional_select(newPos, lastLeaf, isDummy);

        inputnode->pos = fetchPos;

        FetchPath(fetchPos);

        if (!isIncomepleteRead)
        {
            currentLeaf = fetchPos;
        }

        Node<T> *tmpWrite = Node<T>::clone(inputnode);
        tmpWrite->pos = newLeaf;

        Node<T> *res = new Node<T>();
        res->isDummy = true;
        res->index = nextDummyCounter++;
        res->key = nextDummyCounter++;
        bool write = !isRead;

        vector<Node<T> *> nodesList(stash.nodes.begin(), stash.nodes.end());

        if (isIncomepleteRead)
        {
            nodesList.insert(nodesList.end(), incStash.nodes.begin(), incStash.nodes.end());
        }

        for (Node<T> *node : nodesList)
        {
            bool match = Node<T>::CTeq(Bid::CTcmp(node->key, bid), 0) && !node->isDummy;
            node->isDummy = Node<T>::conditional_select(true, node->isDummy, !isDummy && match && write);
            node->pos = Node<T>::conditional_select(newLeaf, node->pos, !isDummy && match);
            bool choice = !isDummy && match && isRead && !node->isDummy;
            res->index = Node<T>::conditional_select((long long)node->index, (long long)res->index, choice);
            res->isDummy = Node<T>::conditional_select(node->isDummy, res->isDummy, choice);
            res->pos = Node<T>::conditional_select((long long)node->pos, (long long)res->pos, choice);
            for (int k = 0; k < res->value.size(); k++)
            {
                res->value[k] = Node<T>::conditional_select(node->value[k], res->value[k], choice);
            }
            res->evictionNode = Node<T>::conditional_select(node->evictionNode, res->evictionNode, choice);
            res->height = Node<T>::conditional_select(node->height, res->height, choice);
            res->leftPos = Node<T>::conditional_select(node->leftPos, res->leftPos, choice);
            res->rightPos = Node<T>::conditional_select(node->rightPos, res->rightPos, choice);
            for (int k = 0; k < res->key.id.size(); k++)
            {
                res->key.id[k] = Node<T>::conditional_select(node->key.id[k], res->key.id[k], choice);
            }
            for (int k = 0; k < res->leftID.id.size(); k++)
            {
                res->leftID.id[k] = Node<T>::conditional_select(node->leftID.id[k], res->leftID.id[k], choice);
            }
            for (int k = 0; k < res->rightID.id.size(); k++)
            {
                res->rightID.id[k] = Node<T>::conditional_select(node->rightID.id[k], res->rightID.id[k], choice);
            }
        }

        if (!isIncomepleteRead)
        {
            stash.insert(tmpWrite);
        }
        else
        {
            incStash.insert(tmpWrite);
        }

        if (!isIncomepleteRead)
        {
            evict(evictBuckets);
        }
        else
        {
            for (Node<T> *item : incStash.nodes)
            {
                delete item;
            }
            incStash.nodes.clear();
        }

        isIncomepleteRead = false;

        return res;
    }

    Node<T> *ReadWrite(Bid bid, unsigned long long lastLeaf, unsigned long long newLeaf, bool isDummy, unsigned long long newChildPos, Bid targetNode)
    {
        if (bid == 0)
        {
            printf("bid is 0 dummy is:%d\n", isDummy ? 1 : 0);
            throw runtime_error("Node id is not set");
        }
        accessCounter++;

        unsigned long long newPos = RandomPath();
        unsigned long long fetchPos = Node<T>::conditional_select(newPos, lastLeaf, isDummy);

        FetchPath(fetchPos);

        currentLeaf = fetchPos;

        Node<T> *res = new Node<T>();
        res->isDummy = true;
        res->index = nextDummyCounter++;
        res->key = nextDummyCounter++;

        for (Node<T> *node : stash.nodes)
        {
            bool match = Node<T>::CTeq(Bid::CTcmp(node->key, bid), 0) && !node->isDummy;
            node->pos = Node<T>::conditional_select(newLeaf, node->pos, !isDummy && match);

            bool choice = !isDummy && match && !node->isDummy;

            bool leftChild = Node<T>::CTeq(Bid::CTcmp(node->key, targetNode), 1);
            bool rightChild = Node<T>::CTeq(Bid::CTcmp(node->key, targetNode), -1);

            res->index = Node<T>::conditional_select((long long)node->index, (long long)res->index, choice);
            res->isDummy = Node<T>::conditional_select(node->isDummy, res->isDummy, choice);
            res->pos = Node<T>::conditional_select((long long)node->pos, (long long)res->pos, choice);
            for (int k = 0; k < res->value.size(); k++)
            {
                res->value[k] = Node<T>::conditional_select(node->value[k], res->value[k], choice);
            }
            res->evictionNode = Node<T>::conditional_select(node->evictionNode, res->evictionNode, choice);
            res->height = Node<T>::conditional_select(node->height, res->height, choice);
            res->leftPos = Node<T>::conditional_select(node->leftPos, res->leftPos, choice);
            res->rightPos = Node<T>::conditional_select(node->rightPos, res->rightPos, choice);
            for (int k = 0; k < res->key.id.size(); k++)
            {
                res->key.id[k] = Node<T>::conditional_select(node->key.id[k], res->key.id[k], choice);
            }
            for (int k = 0; k < res->leftID.id.size(); k++)
            {
                res->leftID.id[k] = Node<T>::conditional_select(node->leftID.id[k], res->leftID.id[k], choice);
            }
            for (int k = 0; k < res->rightID.id.size(); k++)
            {
                res->rightID.id[k] = Node<T>::conditional_select(node->rightID.id[k], res->rightID.id[k], choice);
            }

            // these 2 should be after result set(here is correct)
            node->leftPos = Node<T>::conditional_select(newChildPos, node->leftPos, !isDummy && match && leftChild);
            node->rightPos = Node<T>::conditional_select(newChildPos, node->rightPos, !isDummy && match && rightChild);

            if (!isDummy && match)
            {
                // printf("previous pos:%lld new pos:%lld\n",lastLeaf,newLeaf);
                // printf("in read and set-node:%d:%d:%d:%d:%d:%d:%d\n", node->key.getValue(), node->height, node->pos, node->leftID.getValue(), node->leftPos, node->rightID.getValue(), node->rightPos);
                // printf("in read and set-res:%d:%d:%d:%d:%d:%d:%d\n", res->key.getValue(), res->height, res->pos, res->leftID.getValue(), res->leftPos, res->rightID.getValue(), res->rightPos);
            }
        }

        evict(evictBuckets);
        return res;
    }

    Node<T> *ReadWrite(Bid bid, Node<T> *inputnode, unsigned long long lastLeaf, unsigned long long newLeaf, bool isRead, bool isDummy, array<byte_t, sizeof(T)> value, bool overwrite, bool isIncRead)
    {
        if (bid == 0)
        {
            printf("bid is 0 dummy is:%d\n", isDummy ? 1 : 0);
            throw runtime_error("Node id is not set");
        }
        accessCounter++;
        isIncomepleteRead = isIncRead;

        unsigned long long newPos = RandomPath();
        unsigned long long fetchPos = Node<T>::conditional_select(newPos, lastLeaf, isDummy);

        inputnode->pos = fetchPos;

        FetchPath(fetchPos);

        if (!isIncomepleteRead)
        {
            currentLeaf = fetchPos;
        }

        Node<T> *tmpWrite = Node<T>::clone(inputnode);
        tmpWrite->pos = newLeaf;

        Node<T> *res = new Node<T>();
        res->isDummy = true;
        res->index = nextDummyCounter++;
        res->key = nextDummyCounter++;
        bool write = !isRead;

        vector<Node<T> *> nodesList(stash.nodes.begin(), stash.nodes.end());

        if (isIncomepleteRead)
        {
            nodesList.insert(nodesList.end(), incStash.nodes.begin(), incStash.nodes.end());
        }

        for (Node<T> *node : nodesList)
        {
            bool match = Node<T>::CTeq(Bid::CTcmp(node->key, bid), 0) && !node->isDummy;
            node->isDummy = Node<T>::conditional_select(true, node->isDummy, !isDummy && match && write);
            node->pos = Node<T>::conditional_select(newLeaf, node->pos, !isDummy && match);
            for (int k = 0; k < res->value.size(); k++)
            {
                node->value[k] = Node<T>::conditional_select(value[k], node->value[k], !isDummy && match && overwrite);
            }
            bool choice = !isDummy && match && isRead && !node->isDummy;
            res->index = Node<T>::conditional_select((long long)node->index, (long long)res->index, choice);
            res->isDummy = Node<T>::conditional_select(node->isDummy, res->isDummy, choice);
            res->pos = Node<T>::conditional_select((long long)node->pos, (long long)res->pos, choice);
            for (int k = 0; k < res->value.size(); k++)
            {
                res->value[k] = Node<T>::conditional_select(node->value[k], res->value[k], choice);
            }
            res->evictionNode = Node<T>::conditional_select(node->evictionNode, res->evictionNode, choice);
            res->height = Node<T>::conditional_select(node->height, res->height, choice);
            res->leftPos = Node<T>::conditional_select(node->leftPos, res->leftPos, choice);
            res->rightPos = Node<T>::conditional_select(node->rightPos, res->rightPos, choice);
            for (int k = 0; k < res->key.id.size(); k++)
            {
                res->key.id[k] = Node<T>::conditional_select(node->key.id[k], res->key.id[k], choice);
            }
            for (int k = 0; k < res->leftID.id.size(); k++)
            {
                res->leftID.id[k] = Node<T>::conditional_select(node->leftID.id[k], res->leftID.id[k], choice);
            }
            for (int k = 0; k < res->rightID.id.size(); k++)
            {
                res->rightID.id[k] = Node<T>::conditional_select(node->rightID.id[k], res->rightID.id[k], choice);
            }
        }

        if (!isIncomepleteRead)
        {
            stash.insert(tmpWrite);
        }
        else
        {
            incStash.insert(tmpWrite);
        }

        if (!isIncomepleteRead)
        {
            evict(evictBuckets);
        }
        else
        {
            for (Node<T> *item : incStash.nodes)
            {
                delete item;
            }
            incStash.nodes.clear();
        }

        isIncomepleteRead = false;
        return res;
    }

    void start(bool isBatchWrite)
    {
        this->batchWrite = isBatchWrite;
        readCnt = 0;
        accessCounter = 0;
    }

    void prepareForEvictionTest()
    {
        long long leaf = 10;
        currentLeaf = leaf;
        Node<T> *nd = new Node<T>();
        nd->isDummy = false;
        nd->evictionNode = GetNodeOnPath(leaf, depth);
        nd->index = 1;
        nextDummyCounter++;
        nd->pos = leaf;
        stash.insert(nd);
        for (int i = 0; i <= Z * depth; i++)
        {
            Node<T> *n = new Node<T>();
            n->isDummy = true;
            n->evictionNode = GetNodeOnPath(leaf, depth);
            n->index = nextDummyCounter;
            nextDummyCounter++;
            n->pos = leaf;
            stash.insert(n);
        }
    }

    void evict(bool evictBucketsForORAM)
    {
        double time;
        if (profile)
        {
            ocall_start_timer(15);
            ocall_start_timer(10);
        }

        vector<long long> firstIndexes;
        long long tmpleaf = currentLeaf;
        tmpleaf += bucketCount / 2;
        firstIndexes.push_back(tmpleaf);

        for (int d = depth - 1; d >= 0; d--)
        {
            tmpleaf = (tmpleaf + 1) / 2 - 1;
            firstIndexes.push_back(tmpleaf);
        }

        for (Node<T> *node : stash.nodes)
        {
            long long xorVal = 0;
            xorVal = Node<T>::conditional_select((unsigned long long)0, node->pos ^ currentLeaf, node->isDummy);
            long long indx = 0;

            indx = (long long)floor(log2(Node<T>::conditional_select(xorVal, (long long)1, Node<T>::CTcmp(xorVal, 0))));
            indx = indx + Node<T>::conditional_select(1, 0, Node<T>::CTcmp(xorVal, 0));

            for (long long i = 0; i < firstIndexes.size(); i++)
            {
                bool choice = Node<T>::CTeq(i, indx);
                long long value = firstIndexes[i];
                node->evictionNode = Node<T>::conditional_select(firstIndexes[indx], node->evictionNode, !node->isDummy && choice);
            }
        }

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Assigning stash blocks to lowest possible level:%f\n", time);
            ocall_start_timer(10);
        }

        long long node = currentLeaf + bucketCount / 2;
        for (int d = (int)depth; d >= 0; d--)
        {
            for (int j = 0; j < Z; j++)
            {
                Node<T> *dummy = new Node<T>();
                dummy->index = nextDummyCounter;
                nextDummyCounter++;
                dummy->evictionNode = node;
                dummy->isDummy = true;
                stash.nodes.push_back(dummy);
            }
            node = (node + 1) / 2 - 1;
        }

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Creating Dummy Blocks for each Bucket:%f\n", time);
            ocall_start_timer(10);
        }

        ObliviousOperations<T>::oblixmergesort(&stash.nodes);

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("First Oblivious Sort: %f\n", time);
            ocall_start_timer(10);
        }

        long long currentID = GetNodeOnPath(currentLeaf, depth);
        int level = depth;
        int counter = 0;

        for (unsigned long long i = 0; i < stash.nodes.size(); i++)
        {
            Node<T> *curNode = stash.nodes[i];
            bool firstCond = (!Node<T>::CTeq(Node<T>::CTcmp(counter - (depth - level) * Z, Z), -1));
            bool secondCond = Node<T>::CTeq(Node<T>::CTcmp(curNode->evictionNode, currentID), 0);
            bool thirdCond = (!Node<T>::CTeq(Node<T>::CTcmp(counter, Z * depth), -1)) || curNode->isDummy;
            bool fourthCond = Node<T>::CTeq(curNode->evictionNode, currentID);

            long long tmpEvictionNode = GetNodeOnPath(currentLeaf, depth - (int)floor(counter / Z));
            long long tmpcurrentID = GetNodeOnPath(currentLeaf, level - 1);
            curNode->evictionNode = Node<T>::conditional_select((long long)-1, curNode->evictionNode, firstCond && secondCond && thirdCond);
            curNode->evictionNode = Node<T>::conditional_select(tmpEvictionNode, curNode->evictionNode, firstCond && secondCond && !thirdCond);
            counter = Node<T>::conditional_select(counter + 1, counter, firstCond && secondCond && !thirdCond);
            counter = Node<T>::conditional_select(counter + 1, counter, !firstCond && fourthCond);
            level = Node<T>::conditional_select(level - 1, level, firstCond && !secondCond);
            i = Node<T>::conditional_select(i - 1, i, firstCond && !secondCond);
            currentID = Node<T>::conditional_select(tmpcurrentID, currentID, firstCond && !secondCond);

            //        if (firstCond) {
            //            if (secondCond) {
            //                if (thirdCond) {
            //                    long long tmpEvictionNode = GetNodeOnPath(currentLeaf, depth - (int) floor(counter / Z));
            //                    curNode->evictionNode = -1;
            //                    counter = counter;
            //                    level = level;
            //                    i = i;
            //                } else {
            //                    long long tmpEvictionNode = GetNodeOnPath(currentLeaf, depth - (int) floor(counter / Z));
            //                    curNode->evictionNode = tmpEvictionNode;
            //                    counter++;
            //                    level = level;
            //                    i = i;
            //                }
            //            } else {
            //                currentID = GetNodeOnPath(currentLeaf, level - 1);
            //                curNode->evictionNode = curNode->evictionNode;
            //                counter = counter;
            //                level--;
            //                i--;
            //            }
            //
            //        } else if (curNode->evictionNode == currentID) {
            //            long long tmpID = GetNodeOnPath(currentLeaf, level - 1);
            //            curNode->evictionNode = curNode->evictionNode;
            //            counter++;
            //            level = level;
            //            i = i;
            //        } else {
            //            long long tmpID = GetNodeOnPath(currentLeaf, level - 1);
            //            curNode->evictionNode = curNode->evictionNode;
            //            counter = counter;
            //            level = level;
            //            i = i;
            //        }
        }

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Sequential Scan on Stash Blocks to assign blocks to blocks:%f\n", time);
            ocall_start_timer(10);
        }

        ObliviousOperations<T>::oblixmergesort(&stash.nodes);

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Oblivious Compaction: %f\n", time);
            ocall_start_timer(10);
        }

        unsigned int j = 0;
        Bucket *bucket = new Bucket();
        for (int i = 0; i < (depth + 1) * Z; i++)
        {
            Node<T> *cureNode = stash.nodes[i];
            long long curBucketID = cureNode->evictionNode;
            Block &curBlock = (*bucket)[j];
            curBlock.data.resize(blockSize, 0);
            block tmp = convertNodeToBlock(cureNode);
            curBlock.id = Node<T>::conditional_select((unsigned long long)0, cureNode->index, cureNode->isDummy);
            for (int k = 0; k < tmp.size(); k++)
            {
                curBlock.data[k] = Node<T>::conditional_select(curBlock.data[k], tmp[k], cureNode->isDummy);
            }
            delete cureNode;
            j++;

            if (j == Z)
            {
                if (virtualStorage.count(curBucketID) != 0)
                {
                    virtualStorage.erase(curBucketID);
                }
                virtualStorage[curBucketID] = (*bucket);
                delete bucket;
                bucket = new Bucket();
                j = 0;
            }
        }
        delete bucket;

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Creating Buckets to write:%f\n", time);
            ocall_start_timer(10);
        }

        stash.nodes.erase(stash.nodes.begin(), stash.nodes.begin() + ((depth + 1) * Z));

        for (unsigned int i = PERMANENT_STASH_SIZE; i < stash.nodes.size(); i++)
        {
            delete stash.nodes[i];
        }
        stash.nodes.erase(stash.nodes.begin() + PERMANENT_STASH_SIZE, stash.nodes.end());

        nextDummyCounter = INF;

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Padding stash:%f\n", time);
            ocall_start_timer(10);
        }

        if (evictBucketsForORAM)
        {
            EvictBuckets();
        }

        if (profile)
        {
            ocall_stop_timer(&time, 10);
            printf("Out of SGX memory write:%f\n", time);
        }

        evictcount++;

        if (profile)
        {
            ocall_stop_timer(&time, 15);
            evicttime += time;
            printf("eviction time:%f\n", time);
        }
    }

    void finilize(bool noDummyOp = false)

    {
        if (!noDummyOp && stashCounter == 100)
        {
            stashCounter = 0;
            EvictBuckets();
        }
        else
        {
            stashCounter++;
        }
    }
    bool profile = false;
};

#endif
