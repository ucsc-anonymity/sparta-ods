#include "Dassl.hpp"

Dassl::Dassl(unsigned long long n, unsigned long long m)
{
    num_users = n;
    num_messages = m;

    bytes<Key> tmpkey{0};
    user_store = new OMAP(n, tmpkey);
    message_store = new std::map<unsigned long long, MessageNode>();
}

Dassl::~Dassl()
{
    delete user_store;
    delete message_store;
}

void Dassl::registerUser(unsigned long long user_id)
{
    unsigned long long next_send;
    sgx_read_rand((unsigned char *)&next_send, sizeof(unsigned long long));

    UserRecord n = {next_send, next_send};
    Bid id(user_id);
    user_store->insert(id, n.serialize());
    // vector<byte_t> r = user_store->find(id);
    // UserRecord d = UserRecord::deserialize(r);
    // printf("%llu, %llu", d.next_fetch, d.next_send);
    // for (const auto &pair : *user_store)
    // {
    //     printf("%llx: %llx %llx\n", pair.first, pair.second.next_fetch_idx, pair.second.next_send_idx);
    // }
}

// void Dassl::processSend(unsigned long long receiver, message m)
// {
//     unsigned long long next_send;
//     sgx_read_rand((unsigned char *)&next_send, sizeof(unsigned long long));

//     UserRecord &user = user_store->at(receiver);
//     unsigned long long send_idx = user.next_send;
//     user.next_send = next_send;

//     MessageNode node = {m, next_send};
//     message_store->insert(std::make_pair(send_idx, node));
//     // for (const auto &pair : *user_store)
//     // {
//     //     printf("%llx: %llx %llx\n", pair.first, pair.second.next_fetch_idx, pair.second.next_send_idx);
//     // }

//     // for (const auto &pair : *message_store)
//     // {
//     //     printf("%llx: %llu %llx\n", pair.first, pair.second.m, pair.second.next);
//     // }
//     // printf("\n");
// }

// void Dassl::processFetch(unsigned long long receiver, vector<message> &result)
// {
//     UserRecord &user = user_store->at(receiver);
//     unsigned long long curr = user.next_fetch;
//     for (int i = 0; i < result.capacity(); i++)
//     {
//         message m;
//         if (curr != user.next_send)
//         {
//             MessageNode &node = message_store->at(curr);
//             m = node.m;
//             curr = node.next;
//         }
//         else
//         {
//             m = 0;
//             curr = curr;
//         }
//         result[i] = m;
//     }
//     user.next_fetch = curr;
// }