#ifndef RAMSTOREENCLAVEINTERFACE_H
#define RAMSTOREENCLAVEINTERFACE_H
#include "RAMStore.hpp"
#include "Utilities.h"
#include "stdbool.h"

static RAMStore *omap = NULL;
static RAMStore *oram = NULL;

void ocall_setup_ramStore(bool map, size_t num, int size)
{
    if (size != -1)
    {
        if (map)
        {
            omap = new RAMStore(num, size, false);
        }
        else
        {
            oram = new RAMStore(num, size, false);
        }
    }
    else
    {
        if (map)
        {
            omap = new RAMStore(num, size, true);
        }
        else
        {
            oram = new RAMStore(num, size, true);
        }
    }
}

void ocall_nwrite_ramStore(bool map, size_t blockCount, long long *indexes, const char *blk, size_t len)
{
    assert(len % blockCount == 0);
    size_t eachSize = len / blockCount;
    for (unsigned int i = 0; i < blockCount; i++)
    {
        block ciphertext(blk + (i * eachSize), blk + (i + 1) * eachSize);
        if (map)
        {
            omap->Write(indexes[i], ciphertext);
        }
        else
        {

            oram->Write(indexes[i], ciphertext);
        }
    }
}

void ocall_write_rawRamStore(bool map, long long index, const char *blk, size_t len)
{
    size_t eachSize = len;
    block ciphertext(blk, blk + eachSize);

    if (map)
    {
        omap->WriteRawStore(index, ciphertext);
    }
    else
    {
        oram->WriteRawStore(index, ciphertext);
    }
}

void ocall_nwrite_rawRamStore(bool map, size_t blockCount, long long *indexes, const char *blk, size_t len)
{
    assert(len % blockCount == 0);
    size_t eachSize = len / blockCount;
    for (unsigned int i = 0; i < blockCount; i++)
    {
        block ciphertext(blk + (i * eachSize), blk + (i + 1) * eachSize);
        if (map)
        {
            omap->WriteRawStore(indexes[i], ciphertext);
        }
        else
        {
            oram->WriteRawStore(indexes[i], ciphertext);
        }
    }
}

void ocall_nwrite_ramStore_by_client(bool map, vector<long long> *indexes, vector<block> *ciphertexts)
{
    for (unsigned int i = 0; i < (*indexes).size(); i++)
    {
        if (map)
        {
            omap->Write((*indexes)[i], (*ciphertexts)[i]);
        }
        else
        {
            oram->Write((*indexes)[i], (*ciphertexts)[i]);
        }
    }
}

void ocall_nwrite_raw_ramStore(bool map, vector<block> *ciphertexts)
{
    for (unsigned int i = 0; i < (*ciphertexts).size(); i++)
    {
        if (map)
        {
            omap->WriteRawStore(i, (*ciphertexts)[i]);
        }
        else
        {
            oram->WriteRawStore(i, (*ciphertexts)[i]);
        }
    }
}

size_t ocall_nread_ramStore(bool map, size_t blockCount, long long *indexes, char *blk, size_t len)
{
    assert(len % blockCount == 0);
    size_t resLen = -1;
    for (unsigned int i = 0; i < blockCount; i++)
    {
        block ciphertext;
        if (map)
        {
            ciphertext = omap->Read(indexes[i]);
        }
        else
        {
            ciphertext = oram->Read(indexes[i]);
        }
        resLen = ciphertext.size();
        std::memcpy(blk + i * resLen, ciphertext.data(), ciphertext.size());
    }
    return resLen;
}

size_t ocall_read_rawRamStore(bool map, size_t index, char *blk, size_t len)
{
    size_t resLen = -1;
    block ciphertext;
    if (map)
    {
        ciphertext = omap->ReadRawStore(index);
    }
    else
    {
        ciphertext = oram->ReadRawStore(index);
    }
    resLen = ciphertext.size();
    std::memcpy(blk, ciphertext.data(), ciphertext.size());
    return resLen;
}

size_t ocall_nread_rawRamStore(bool map, size_t blockCount, size_t begin, char *blk, size_t len)
{
    assert(len % blockCount == 0);
    size_t resLen = -1;
    size_t rawSize;
    if (map)
    {
        rawSize = omap->tmpstore.size();
    }
    else
    {
        rawSize = oram->tmpstore.size();
    }
    for (unsigned int i = 0; i < blockCount && (begin + i) < rawSize; i++)
    {
        block ciphertext;
        if (map)
        {
            ciphertext = omap->ReadRawStore(i + begin);
        }
        else
        {
            ciphertext = oram->ReadRawStore(i + begin);
        }
        resLen = ciphertext.size();
        std::memcpy(blk + i * resLen, ciphertext.data(), ciphertext.size());
    }
    return resLen;
}

void ocall_initialize_ramStore(bool map, long long begin, long long end, const char *blk, size_t len)
{
    block ciphertext(blk, blk + len);
    for (long long i = begin; i < end; i++)
    {
        if (map)
        {
            omap->Write(i, ciphertext);
        }
        else
        {
            oram->Write(i, ciphertext);
        }
    }
}

void ocall_write_ramStore(bool map, long long index, const char *blk, size_t len)
{
    block ciphertext(blk, blk + len);
    if (map)
    {
        omap->Write(index, ciphertext);
    }
    else
    {
        oram->Write(index, ciphertext);
    }
}
#endif /* RAMSTOREENCLAVEINTERFACE_H */
