#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>

#define KEYRING_PIN NULL

extern keyring_file *keyring; // keyring is global Serval variable

int main ( int argc, char *argv[] ) {
  
  if (argc < 2 || argc > 3) {  /* wrong number of arguments */
    printf("usage: serval-sign <message> [<sid>]\n");
    return 1;
    
  } else {
    unsigned char *sid;
    keyring_identity *new_ident;
    int msg_length = strlen(argv[1]);
    unsigned char *msg = argv[1];
      
    char keyringFile[1024];
    FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // this should target default Serval keyring
    keyring = keyring_open(keyringFile);
    int num_identities = keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
    
    if (argc == 3) {
      sid = argv[2]; // SID to use is given as command-line argument
    } else {
      //create new sid
      int c;
      for(c=0;c<keyring->context_count;c++) { // cycle through the keyring contexts until we find one with room for another identity
	new_ident = keyring_create_identity(keyring,keyring->contexts[c], KEYRING_PIN); // create new Serval identity
	if (new_ident)
	  break;
      }
      if (!new_ident) {
	printf("failed to create new SID\n");
	return 1;
      }
      if (keyring_commit(keyring)) { // need to commit keyring or else new identity won't be saved (needs root permissions)
	printf("Failed to save new SID into keyring...make sure you are running as root!\n");
	return 1;
      }
      sid = alloca_tohex_sid(new_ident->subscriber->sid); // convert SID from binary to hex
    }
    
    unsigned char packedSid[SID_SIZE];
    //int x = stowSid(packedSid,0,alloca_tohex_sid(my_subscriber->sid));
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
    
    //printf("%s\n",msg);
    
    printf("%s\n", alloca_tohex(signed_msg + msg_length, sig_length));
    //printf("%s\n",alloca_tohex_sid(my_subscriber->sid));
    printf("%s\n",sid);
    
    return success;
  }
  
  return 1;
}
