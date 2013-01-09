#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>

#define KEYRING_PIN NULL
#define BUF_SIZE 1024

extern keyring_file *keyring; // keyring is global Serval variable

unsigned char *sid;
unsigned char *msg;
int need_cleanup = 0;

int get_sid(unsigned char *str);
void print_usage();
void get_msg();

int main ( int argc, char *argv[] ) {

  keyring_identity *new_ident;

  switch (argc) {
    default:
      print_usage();
      return 1;
    case 1:
      get_msg();
      break;
    case 2:
      if (!strcmp(argv[1],"-h")) {
	print_usage();
	return 0;
      }
      msg = argv[1];
      break;
    case 3:
      if (strcmp(argv[1],"-s")) {
	print_usage();
	return 1;
      }
      if (get_sid(argv[2]))
	return 1;
      get_msg();
      break;
    case 4:
      if (!strcmp(argv[1],"-s")) {
	if (get_sid(argv[2]))
	  return 1;
	msg = argv[3];
      } else if (!strcmp(argv[2],"-s")) {
	if (get_sid(argv[3]))
	  return 1;
	msg = argv[1];
      } else {
	print_usage();
	return 1;
      }
  }
  
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
  if (need_cleanup) free(msg);
  
  return success;
  
}

int get_sid(unsigned char *str) {
  if (!str_is_subscriber_id(str)) {
    fprintf(stderr,"Invalid SID\n");
    return 1;
  }
  sid = str;
  return 0;
}

void print_usage() {
  printf("usage: serval-sign <message> [-s <sid>]\n");
}

void get_msg() {
  need_cleanup = 1;
  char buffer[BUF_SIZE];
  size_t contentSize = 1; // includes NULL
  msg = malloc(sizeof(char) * BUF_SIZE);
  msg[0] = '\0'; // make null-terminated
  while(fgets(buffer, BUF_SIZE, stdin))
  {
    char *old = msg;
    contentSize += strlen(buffer);
    msg = realloc(msg, contentSize);
    strcat(msg, buffer);
  }
  msg[strlen(msg)-1] = '\0';
}
