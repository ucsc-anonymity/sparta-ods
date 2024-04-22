#include "Enclave.h"
#include <assert.h>
#include <string>
#include "Enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "OMAP/OMAP.hpp"
#include "OMAP/Dassl.hpp"

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int ecall_main(int max_size)
{
    // Dassl dassl(1048567, 2097152);
    Dassl dassl(512, 2048);
    dassl.registerUser(1);
    dassl.registerUser(2);

    vector<message> one(8);
    for (int i = 0; i < 3; i++)
        dassl.processSend(1, i + 1);
    dassl.processFetch(1, one);
    for (auto &item : one)
    {
        printf("%llu\n", item);
    }
    printf("\n");

    vector<message> two(5);
    for (int i = 0; i < 3; i++)
        dassl.processSend(2, i + 1);
    dassl.processFetch(2, two);
    for (auto &item : two)
    {
        printf("%llu\n", item);
    }
    printf("\n");

    for (int i = 4; i < 8; i++)
        dassl.processSend(1, i);
    dassl.processFetch(1, one);
    for (auto &item : one)
    {
        printf("%llu\n", item);
    }
    return 0;
}
