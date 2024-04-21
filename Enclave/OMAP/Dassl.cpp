#include "Dassl.hpp"
#include "ORAM.hpp"

Dassl::Dassl(unsigned long long n, unsigned long long m)
{
    num_users = n;
    num_messages = m;

    bytes<Key> tmpkey{0};
    user_store = new OMAP<UserRecord>(n, tmpkey);
    message_store = new ORAM<MessageNode>(false, m, tmpkey, false, true);
}

Dassl::~Dassl()
{
    delete user_store;
    delete message_store;
}

void Dassl::registerUser(unsigned long long user_id)
{
    unsigned long long next_send_id = 0;
    sgx_read_rand((unsigned char *)&next_send_id, sizeof(unsigned long long));
    unsigned long long next_send_pos = message_store->RandomPath();

    UserRecord n = {next_send_id, next_send_pos, next_send_id, next_send_pos};
    Bid id(user_id);
    user_store->insert(id, n.serialize());
}

void Dassl::processSend(unsigned long long receiver_id, message m)
{

    // Fetch user record and get the current sending id and position.
    Bid id(receiver_id);
    UserRecord user_rec = UserRecord::deserialize(user_store->find(id));
    unsigned long long curr_send_id = user_rec.next_send_id;
    unsigned long long curr_send_pos = user_rec.next_send_pos;

    // Set the new next_send id and position, then update the user store.
    unsigned long long next_send_id;
    sgx_read_rand((unsigned char *)&next_send_id, sizeof(unsigned long long));
    unsigned long long next_send_pos = message_store->RandomPath();
    user_rec.next_send_id = next_send_id;
    user_rec.next_send_pos = next_send_pos;
    user_store->insert(id, user_rec.serialize());
    user_rec = UserRecord::deserialize(user_store->find(id));

    // Construct the new message node.
    MessageNode message = {m, next_send_id, next_send_pos};
    Bid send_id(curr_send_id);
    Node<MessageNode> *node = new Node<MessageNode>(send_id, message.serialize(), curr_send_pos);

    // dummy is set to true so that the path fetch will be for a random
    // location (oldleaf, 0, gets overwritten with a random value), which
    // fetches this random path from the ORAM. The written node will have
    // send_idx as it's path location, when it gets evicted back to the ORAM.
    message_store->ReadWrite(send_id, node, 0, curr_send_pos, false, false, false);
    delete node;
}

void Dassl::processFetch(unsigned long long receiver, vector<message> &result)
{
    // Fetch the user record and get the next fetch id and pos.
    Bid id(receiver);
    UserRecord user_rec = UserRecord::deserialize(user_store->find(id));

    unsigned long long curr_id = user_rec.next_fetch_id;
    unsigned long long curr_pos = user_rec.next_fetch_pos;

    Node<MessageNode> *res = new Node<MessageNode>();
    // this is oblivious because the result size is public information.
    for (int i = 0; i < result.capacity(); i++)
    {
        message m;
        if (curr_id != user_rec.next_send_id) // this is not oblivious... BAD
        {
            // newleaf does not matter because I will only read each message once.
            Bid cid(curr_id);
            res = message_store->ReadWrite(cid, res, curr_pos, 0, true, false, false);
            vector<byte_t> value(res->value.begin(), res->value.end());
            MessageNode node = MessageNode::deserialize(value);
            m = node.m;
            curr_id = node.next_id;
            curr_pos = node.next_pos;
        }
        else
        {
            m = 0;
        }
        result[i] = m;
    }
    delete res;
}