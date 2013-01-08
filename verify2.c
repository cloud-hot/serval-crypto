#include <stdio.h>
#include <string.h>
#include <poll.h>

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>

#define KEYRING_PIN NULL
#define MAX_SAS_VALIDATION_ATTEMPTS 10
#define BUF_SIZE 1024

void print_usage();
int fetch_next_arg(unsigned char **var, char **argv[]);
void get_msg();
int need_cleanup = 0;

int main ( int argc, char *argv[] ) {

  int sas_validation_attempts = 0, num_identities = 0;
  unsigned char *sid = NULL, *msg = NULL, *sig = NULL;
  
  if (argc != 2 && argc != 5 && argc != 7) {
    print_usage();
    return 1;
  }
  
  while ((argc > 1) && (argv[1][0] == '-')) {
    switch (argv[1][1]) {
      case 'i':
	if (sid || fetch_next_arg(&sid,&argv)) {
	  print_usage();
	  return 1;
	}
	break;
      case 'm':
	if (msg || fetch_next_arg(&msg,&argv)) {
	  print_usage();
	  return 1;
	}
	break;
      case 's':
	if (sig || fetch_next_arg(&sig,&argv)) {
	  print_usage();
	  return 1;
	}
	break;
      default:
	print_usage();
	return 1;
    }
    ++argv;
    --argc;--argc;
  }
  
  if (!msg) get_msg(&msg);
  int msg_length = strlen(msg);
  
  unsigned char bin_sig[SIGNATURE_BYTES];
  fromhexstr(bin_sig,sig,SIGNATURE_BYTES); // convert signature from hex to binary
  
  unsigned char msg_sig[msg_length + SIGNATURE_BYTES];
  strncpy(msg_sig,msg,msg_length);
  strncpy(msg_sig + msg_length,bin_sig,SIGNATURE_BYTES); // append signature to end of message
  int msg_sig_length = strlen(msg_sig);
  
  char keyringFile[1024];
  FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // this should target default Serval keyring
  keyring = keyring_open(keyringFile);
  if (!keyring) {
    fprintf(stderr, "Failed to open Serval keyring\n");
    return 1;
  }
  num_identities = keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
  if (!num_identities) {
    fprintf(stderr, "Failed to unlock any Serval identities\n");
    return 1;
  }
  
  unsigned char packedSid[SID_SIZE];
  stowSid(packedSid,0,sid);
  
  struct subscriber *src_sub = find_subscriber(packedSid, SID_SIZE, 0); // get Serval identity described by given SID
  if (!src_sub) {
    fprintf(stderr, "Failed to fetch Serval subscriber\n");
    return 1;
  }
  //printf("SID: %s\n",alloca_tohex_sid(src_sub->sid));
  
  while (!src_sub->sas_valid && sas_validation_attempts < MAX_SAS_VALIDATION_ATTEMPTS) {
  
    if (keyring_send_sas_request(src_sub)) { // send MDP request for SAS public key of given SID
      printf("sas request failed\n");
      return 1;
    }
    sas_validation_attempts++;
    usleep(100*1000);
  }
  
  if (!src_sub->sas_valid) {
    fprintf(stderr, "Could not validate the signing key!\n");
    return 1;
  }
  
  //printf("SAS: %s\n",alloca_tohex_sid(src_sub->sas_public));
  
  int verdict = crypto_verify_message(src_sub, msg_sig, &msg_sig_length);
  
  if (!verdict) {
    printf("Message verified!\n");
  }
  else {
    printf("Message NOT verified\n");
  }

  keyring_free(keyring);
  if (need_cleanup) free(msg);
  
  return verdict;

}

void print_usage() {
  printf("usage: serval-verify -i <sid> -m <message> -s <signature>\n");
}

int fetch_next_arg(unsigned char **var, char **argv[]) {
  ++(*argv);
  if ((*argv)[1][0] == '-') {
    return 1;
  }
  *var = (*argv)[1];
  return 0;
}

void get_msg(unsigned char **msg) {
  need_cleanup = 1;
  char buffer[BUF_SIZE];
  size_t contentSize = 1; // includes NULL
  *msg = malloc(sizeof(char) * BUF_SIZE);
  (*msg)[0] = '\0'; // make null-terminated
  while(fgets(buffer, BUF_SIZE, stdin))
  {
    char *old = *msg;
    contentSize += strlen(buffer);
    *msg = realloc(*msg, contentSize);
    strcat(*msg, buffer);
  }
  (*msg)[strlen(*msg)-1] = '\0';
}