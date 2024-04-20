// #include <map>
#include <string>
#include "../Enclave.h"
#include "AES.hpp"
#include "OMAP.h"
#include "ORAM.hpp"
#include "Types.hpp"

#define MSG_LEN 1

// typedef std::array<byte_t, MSG_LEN> message;

class Dassl
{
    unsigned long long num_users;
    unsigned long long num_messages;
    OMAP *user_store;
    map<unsigned long long, MessageNode> *message_store;

public:
    Dassl(unsigned long long n, unsigned long long m);
    ~Dassl();
    void registerUser(unsigned long long user_id);
    // void processSend(unsigned long long receiver_id, message m);
    // void processFetch(unsigned long long receiver_id, vector<message> &result);
};