#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>
#include <argp.h>
#include <assert.h>

#include "serval-crypto.h"

extern keyring_file *keyring; // keyring is global Serval variable

int serval_sign(const char *sid, 
	 const size_t sid_len,
	 const unsigned char *msg,
	 const size_t msg_len,
	 char *sig_buffer,
	 const size_t sig_size,
	 const char *keyringName,
	 const size_t keyring_len) {
  
  keyring_identity *new_ident;
  char keyringFile[1024];
  
  assert(msg_len);
  if (sid) assert(sid_len == 2*SID_SIZE);
  
  if (keyringName == NULL || keyring_len == 0) { 
    FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // if no keyring specified, use default keyring
  }
  else { // otherwise, use specified keyring (NOTE: if keyring does not exist, it will be created)
    strncpy(keyringFile,keyringName,keyring_len);
    keyringFile[keyring_len] = '\0';
  }
  
  keyring = keyring_open(keyringFile);
  keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
  
  if (!sid) {
    //create new sid
    int c;
    for(c=0;c<keyring->context_count;c++) { // cycle through the keyring contexts until we find one with room for another identity
      new_ident = keyring_create_identity(keyring,keyring->contexts[c], KEYRING_PIN); // create new Serval identity
      if (new_ident)
	break;
    }
    if (!new_ident) {
      fprintf(stderr, "failed to create new SID\n");
      return 1;
    }
    if (keyring_commit(keyring)) { // need to commit keyring or else new identity won't be saved (needs root permissions)
      fprintf(stderr, "Failed to save new SID into keyring...make sure you are running as root!\n");
      return 1;
    }
    sid = alloca_tohex_sid(new_ident->subscriber->sid); // convert SID from binary to hex
  } else {
    if (!str_is_subscriber_id(sid)) {
      fprintf(stderr,"Invalid SID\n");
      return 1;
    }
  }
  
  unsigned char packedSid[SID_SIZE];
  stowSid(packedSid,0,sid);
  
  unsigned char *key=keyring_find_sas_private(keyring, packedSid, NULL); // get SAS key associated with our SID
  if (!key)
    return 1;
  
  unsigned char hash[crypto_hash_sha512_BYTES]; 
  unsigned long long sig_length = SIGNATURE_BYTES;
  crypto_hash_sha512(hash, msg, msg_len); // create sha512 hash of message, which will then be signed
  
  unsigned char signed_msg[msg_len + sig_length];
  memcpy(signed_msg,msg,msg_len);
  
  int ret = crypto_create_signature(key, hash, crypto_hash_sha512_BYTES, &signed_msg[msg_len], &sig_length); // create signature of message hash, append it to end of message
  
  if (!ret) { //success
    printf("%s\n", alloca_tohex(signed_msg + msg_len, sig_length));
    printf("%s\n",sid);
    if (sig_size > 0) {
      if (sig_size >= 2*sig_length + 1) {
        strncpy(sig_buffer,alloca_tohex(signed_msg + msg_len,sig_length),2*sig_length);
        sig_buffer[2*sig_length] = '\0';
      } else
	fprintf(stderr,"Insufficient signature buffer size\n");
    }
  }
  
  keyring_free(keyring);
  
  return ret;
}
