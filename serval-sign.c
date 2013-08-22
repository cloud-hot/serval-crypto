#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>
#include <argp.h>

#include "serval-crypto.h"

#define KEYRING_PIN NULL

extern keyring_file *keyring; // keyring is global Serval variable

static int get_sid(unsigned char *str, unsigned char **sid);

static struct arguments {
  unsigned char *sid;
  unsigned char *msg;
} arguments;

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  if (state->arg_num > 0)
    return ARGP_ERR_UNKNOWN;
  
  switch (key) {
    case 's':
      arguments->sid = arg;
      break;
    case ARGP_KEY_ARG:
      arguments->msg = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int sign(const char *sid, 
	 size_t sid_len,
	 const char *msg,
	 size_t msg_len) {
  
  keyring_identity *new_ident;
  
  int msg_length = strlen(msg);
  
  char keyringFile[1024];
  FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // this should target default Serval keyring
  keyring = keyring_open(keyringFile);
  int num_identities = keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
  
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
  }
  
  unsigned char packedSid[SID_SIZE];
  int x = stowSid(packedSid,0,sid);
  
  unsigned char *key=keyring_find_sas_private(keyring, packedSid, NULL); // get SAS key associated with our SID
  if (!key)
    return 1;
  
  unsigned char hash[crypto_hash_sha512_BYTES]; 
  unsigned long long sig_length = SIGNATURE_BYTES;
  crypto_hash_sha512(hash, msg, msg_length); // create sha512 hash of message, which will then be signed
  
  unsigned char signed_msg[msg_length + sig_length];
  strncpy(signed_msg,msg,msg_length);
  
  int success = crypto_create_signature(key, hash, crypto_hash_sha512_BYTES, &signed_msg[msg_length], &sig_length); // create signature of message hash, append it to end of message
  
  printf("%s\n", alloca_tohex(signed_msg + msg_length, sig_length));
  printf("%s\n",sid);
  
  keyring_free(keyring);
  
  return success;
}

#ifndef SHARED
int main ( int argc, char *argv[] ) {

  int need_cleanup = 0;

  const char *argp_program_version = "2.1";
  static char doc[] = "Serval Sign";
  static struct argp_option options[] = {
    {"sid", 's', "SID", 0, "Existing Serval ID (SID) to be used to sign the message. If missing, a new SID will be created to sign the message." },
    { 0 }
  };
  
  arguments.msg = NULL;
  arguments.sid = NULL;
  
  static struct argp argp = { options, parse_opt, "MESSAGE", doc };
  
  argp_parse (&argp, argc, argv, 0, 0, &arguments);
  
  if (arguments.sid && !str_is_subscriber_id(arguments.sid)) {
    fprintf(stderr,"Invalid SID\n");
    return 1;
  }
  
  if (!arguments.msg) {
    get_msg(&(arguments.msg));
    need_cleanup = 1;
  }
    
 int verdict = sign(arguments.sid,arguments.sid ? strlen(arguments.sid) : 0,arguments.msg,strlen(arguments.msg));
  
 if (need_cleanup) free(arguments.msg);
 
 return verdict;
 
}
#endif
