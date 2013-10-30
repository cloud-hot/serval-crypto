#ifndef SERVAL_CRYPTO_H
#define SERVAL_CRYPTO_H

#ifdef USESYSLOG
#define LOG(M, ...) syslog(LOG_DEBUG, M, ##__VA_ARGS__)
#else
#define LOG(M, ...) fprintf(stderr, "[SERVAL_CRYPTO] " M, ##__VA_ARGS__)
#endif

#if defined(NDEBUG)
#define DEBUG(M, ...)
#else
#define DEBUG(M, ...) LOG("(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

void get_msg(unsigned char **msg);

int sign(const char *sid, size_t sid_len, const char *msg, size_t msg_len, char *sig_buffer, size_t sig_size);

int verify(const char *sid,size_t sid_len,const char *msg,size_t msg_len,const char *sig,size_t sig_len);

#endif