/* vim: set ts=2 expandtab: */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <poll.h>
#include <assert.h>

#include "verify.h"
// GOOD
#define __INSTANCE_PATH "/home/hawkinsw/code/serval/serval-dna/serval-dna/instance-path/"
// BAD
//#define __INSTANCE_PATH "/hom/hawkinsw/code/serval/serval-dna/serval-dna/instance-path/"

// GOOD
#define SID "4DD9FEC205D2195C6D7095DCE8DC0FF624FD4DC36631ED673EEE631387D44925"
// BAD
//#define SID "A3A440A7EA07C14505C9AA2658DD6A387E30E9C25FD7767529A3E4E7D63DD13"

#define MAX_SAS_VALIDATION_ATTEMPTS 3

extern keyring_file *keyring;

void usage(char *argv[]) {
  printf("%s <sid> <message> <signature>\n", argv[0]);
}

struct subscriber *
read_subscriber_from_servald(keyring_file *keyring, const char *sid)
{
  const char *pins = {"",};
  unsigned char stowedSid[SID_SIZE];
  unsigned char *found_private_key = NULL;
  int found_private_key_len = 0;
  int cn = 0, in = 0, kp = 0;
 
  stowSid(stowedSid, 0, sid);
  
  if (!keyring_find_sid(keyring, &cn, &in, &kp, stowedSid))
  {
    fprintf(stderr, "[MDP] sid not found\n");
    return NULL;
  }

  if (!keyring_find_sas_private(keyring, stowedSid, NULL))
    fprintf(stderr, "No private SAS found");

  return keyring->contexts[cn]->identities[in]->subscriber;
}

int main(int argc, char *argv[]) {
  char *sid, *message, *signatureHex;
  const char *pins = {"",};
  unsigned char *stowedSid[SID_SIZE];
  struct subscriber *subscriber;
  int return_value = 0;
  int message_len = 0, combined_message_len = 0;
  char *combined_message = NULL;
  char *signature[SIGNATURE_BYTES];
  int sas_validation_attempts = 0;

  if (argc != 4) {
    usage(argv);
    return -1;
  }

#ifdef SID
  sid = SID;
#else
  sid = argv[1];
#endif
  message = argv[2];
  signatureHex = argv[3];
  
  printf("sid: %s\n", sid);
  printf("message: %s\n", message);
  printf("signatureHex: %s\n", signatureHex);

  if (fromhexstr(signature, signatureHex, SIGNATURE_BYTES)) {
    printf("error converting from hex!\n");
  }

  message_len = strlen(message);
  combined_message_len = message_len + SIGNATURE_BYTES;
  combined_message = (char*)calloc(combined_message_len + 1, sizeof(char));

  memcpy(combined_message, message, message_len);
  memcpy(combined_message + message_len, signature, SIGNATURE_BYTES);

#ifdef __INSTANCE_PATH
  serval_setinstancepath(__INSTANCE_PATH);
#endif

  keyring = keyring_open_with_pins(pins);
  assert(keyring);

  subscriber = read_subscriber_from_servald(keyring, sid);
  assert(subscriber);

  while (!subscriber->sas_valid && 
          sas_validation_attempts < MAX_SAS_VALIDATION_ATTEMPTS) {
    printf("Sending a SAS request ... \n");
    if (keyring_send_sas_request(subscriber)) {
      printf("An error occurred sending the SAS request!\n");
      break;
    }
    sas_validation_attempts++;
  }

  if (!subscriber->sas_valid) {
    printf("Could not validate the signing key!\n");
  }

  return_value = crypto_verify_message(subscriber, 
    combined_message, 
    &combined_message_len);

  if (!return_value) {
    printf("Message verified!\n");
  }
  else {
    printf("Message NOT verified\n");
  }

  keyring_free(keyring);
  free(combined_message);
	return return_value;
}
