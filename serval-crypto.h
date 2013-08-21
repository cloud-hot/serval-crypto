#ifndef SERVAL_CRYPTO_H
#define SERVAL_CRYPTO_H

void get_msg(unsigned char **msg);

int sign(const char *sid, size_t sid_len, const char *msg, size_t msg_len);

int verify(const char *sid,size_t sid_len,const char *msg,size_t msg_len,const char *sig,size_t sig_len);

#endif