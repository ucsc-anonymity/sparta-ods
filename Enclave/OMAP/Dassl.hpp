// #include <map>
#include "../Enclave.h"
#include "AES.hpp"
#include "OMAP.h"
#include "ORAM.hpp"

#define MSG_LEN 1

// typedef std::array<byte_t, MSG_LEN> message;
typedef unsigned long long message;

struct MessageNode
{
    // unsigned long long next_pos;
    message m;
    unsigned long long next;
};

struct UserRecord
{
    unsigned long long next_fetch;
    unsigned long long next_send;
    // unsigned long long next_write_pos;
    // unsigned long long next_read_pos;
};

class Dassl
{
    unsigned long long num_users;
    unsigned long long num_messages;
    map<unsigned long long, UserRecord> *user_store;
    map<unsigned long long, MessageNode> *message_store;

public:
    Dassl(unsigned long long n, unsigned long long m);
    ~Dassl();
    void registerUser(unsigned long long user_id);
    void processSend(unsigned long long receiver_id, message m);
    void processFetch(unsigned long long receiver_id, vector<message> &result);
};