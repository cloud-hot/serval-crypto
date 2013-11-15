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

#define CLEAN_ERRNO() (errno == 0 ? "None" : strerror(errno))

#define ERROR(M, ...) LOG("(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)

#define CHECK(A, M, ...) if(!(A)) { ERROR(M, ##__VA_ARGS__); errno=0; goto error; }

#define KEYRING_PIN NULL

void get_msg(char **msg);

int serval_verify(const char *sid,
		  const size_t sid_len,
		  const unsigned char *msg,
		  const size_t msg_len,
		  const char *sig,
		  const size_t sig_len,
		  const char *keyringName,
		  const size_t keyring_len);

int serval_sign(const char *sid, 
		const size_t sid_len,
		const unsigned char *msg,
		const size_t msg_len,
		char *sig_buffer,
		const size_t sig_size,
		const char *keyringName,
		const size_t keyring_len);

#endif
