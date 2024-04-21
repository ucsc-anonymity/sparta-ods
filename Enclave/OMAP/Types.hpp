#ifndef TYPES
#define TYPES

#include <array>
#include <vector>
#include <iostream>

// The main type for passing around raw file data
#define ID_SIZE 10

using byte_t = uint8_t;
using block = std::vector<byte_t>;

template <size_t N>
using bytes = std::array<byte_t, N>;

// A bucket contains a number of Blocks
constexpr int Z = 4;

enum Op
{
    READ,
    WRITE
};

template <typename T>
std::array<byte_t, sizeof(T)> to_bytes(const T &object)
{
    std::array<byte_t, sizeof(T)> bytes;

    const byte_t *begin = reinterpret_cast<const byte_t *>(std::addressof(object));
    const byte_t *end = begin + sizeof(T);
    std::copy(begin, end, std::begin(bytes));

    return bytes;
}

template <typename T>
T &from_bytes(const std::array<byte_t, sizeof(T)> &bytes, T &object)
{
    byte_t *begin_object = reinterpret_cast<byte_t *>(std::addressof(object));
    std::copy(std::begin(bytes), std::end(bytes), begin_object);

    return object;
}

typedef unsigned long long message;

struct MessageNode
{
    message m;
    unsigned long long next_id;
    unsigned long long next_pos;
    std::array<byte_t, 248> dummy; // enough for a 256 byte message (248 + m)
    std::vector<byte_t> serialize()
    {
        const char *s = reinterpret_cast<const char *>(this);
        std::vector<byte_t> b = std::vector<byte_t>(s, s + sizeof(MessageNode));
        return b;
    }
    static MessageNode deserialize(std::vector<byte_t> bytes)
    {
        if (bytes.size() != sizeof(MessageNode))
        {
            throw std::invalid_argument("Invalid size for deserialization");
        }

        const MessageNode *nodePtr = reinterpret_cast<const MessageNode *>(bytes.data());
        return *nodePtr;
    }
};

struct UserRecord
{
    unsigned long long next_fetch_id;
    unsigned long long next_fetch_pos;
    unsigned long long next_send_id;
    unsigned long long next_send_pos;

    std::vector<byte_t> serialize()
    {
        const char *s = reinterpret_cast<const char *>(this);
        std::vector<byte_t> b = std::vector<byte_t>(s, s + sizeof(UserRecord));
        return b;
    }

    static UserRecord deserialize(std::vector<byte_t> bytes)
    {
        if (bytes.size() != sizeof(UserRecord))
        {
            throw std::invalid_argument("Invalid size for deserialization");
        }

        const UserRecord *nodePtr = reinterpret_cast<const UserRecord *>(bytes.data());
        return *nodePtr;
    }
    // unsigned long long next_write_pos;
    // unsigned long long next_read_pos;
};

#endif