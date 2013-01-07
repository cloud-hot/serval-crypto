#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>

#define KEYRING_PIN NULL

int main ( int argc, char *argv[] ) {

  if (argc != 4) {
    printf("usage: serval-verify <sid> <message> <signature>\n");
    return 1;
  }
  unsigned char *sid = argv[1];
  unsigned char *msg = argv[2];
  int msg_length = strlen(msg);
  unsigned char *sig = argv[3];
  
  unsigned char bin_sig[SIGNATURE_BYTES];
  fromhex(bin_sig,sig,SIGNATURE_BYTES); // convert signature from hex to binary
  
  unsigned char msg_sig[msg_length + SIGNATURE_BYTES];
  strncpy(msg_sig,msg,msg_length);
  strncpy(msg_sig + msg_length,bin_sig,SIGNATURE_BYTES); // append signature to end of message
  int msg_sig_length = strlen(msg_sig);
  
  char keyringFile[1024];
  FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // this should target default Serval keyring
  keyring = keyring_open(keyringFile);
  int num_identities = keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
  
  unsigned char packedSid[SID_SIZE];
  stowSid(packedSid,0,sid);
  
  struct subscriber *src_sub = find_subscriber(packedSid, SID_SIZE, 0); // get Serval identity described by given SID
  //printf("SID: %s\n",alloca_tohex_sid(src_sub->sid));
  
  if (keyring_send_sas_request(src_sub)) { // send MDP request for SAS public key of given SID
    printf("sas request failed\n");
    return 1;
  }
  
  //printf("SAS: %s\n",alloca_tohex_sid(src_sub->sas_public));
  
  int verdict = crypto_verify_message(src_sub, msg_sig, &msg_sig_length);
  
  //printf("VERDICT: %d\n",verdict);

  return verdict;

}