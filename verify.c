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

int keyring_send_sas_request_client(struct subscriber *subscriber){
  int ret, client_port, found = 0;
  unsigned char srcsid[SID_SIZE];
  time_ms_t now = gettime_ms();
  
  if (overlay_mdp_getmyaddr(0,srcsid)) {
    printf("Could not get local address");
    return 1;
  }

  if (subscriber->sas_valid)
    return 0;
  
  if (now < subscriber->sas_last_request + 100){
    printf("Too soon to ask for SAS mapping again\n");
    return 0;
  }
  
  if (!my_subscriber) {
    printf("couldn't request SAS (I don't know who I am)\n");
    return 1;
  }
  
  printf("Requesting SAS mapping for SID=%s\n", alloca_tohex_sid(subscriber->sid));
  
  if (overlay_mdp_bind(my_subscriber->sid,(client_port=32768+(random()&32767)))) {
    printf("Failed to bind to client socket\n");
    return 1;
  }

/* request mapping (send request auth-crypted). */
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));  

  mdp.packetTypeAndFlags=MDP_TX;
  mdp.out.queue=OQ_MESH_MANAGEMENT;
  bcopy(subscriber->sid,mdp.out.dst.sid,SID_SIZE);
  mdp.out.dst.port=MDP_PORT_KEYMAPREQUEST;
  mdp.out.src.port=client_port;
  bcopy(srcsid,mdp.out.src.sid,SID_SIZE);
  mdp.out.payload_length=1;
  mdp.out.payload[0]=KEYTYPE_CRYPTOSIGN;
  
  ret = overlay_mdp_send(&mdp, 0,0);
  if (ret) {
    printf("Failed to send SAS resolution request: %d\n", ret);
    if (mdp.packetTypeAndFlags==MDP_ERROR)
	{
	  printf("  MDP Server error #%d: '%s'\n",
	       mdp.error.error,mdp.error.message);
	}
    return 1;
  }
  
  time_ms_t timeout = now + 5000;

  while(now<timeout) {
    time_ms_t timeout_ms = timeout - gettime_ms();
    int result = overlay_mdp_client_poll(timeout_ms);
    
    if (result>0) {
      int ttl=-1;
      if (overlay_mdp_recv(&mdp, client_port, &ttl)==0) {
	switch(mdp.packetTypeAndFlags&MDP_TYPE_MASK) {
	  case MDP_ERROR:
	    printf("overlay_mdp_recv: %s (code %d)\n", mdp.error.message, mdp.error.error);
	    break;
	  case MDP_TX:
	  {
	    printf("Received SAS mapping response\n");
	    found = 1;
	    break;
	  }
	  break;
	  default:
	    printf("overlay_mdp_recv: Unexpected MDP frame type 0x%x\n", mdp.packetTypeAndFlags);
	    break;
	}
	if (found) break;
      }
    }
    now=gettime_ms();
    if (servalShutdown)
      break;
  }

  unsigned keytype = mdp.out.payload[0];
  
  if (keytype!=KEYTYPE_CRYPTOSIGN) {
    printf("Ignoring SID:SAS mapping with unsupported key type %u\n", keytype);
    return 1;
  }
  
  if (mdp.out.payload_length < 1 + SAS_SIZE) {
    printf("Truncated key mapping announcement? payload_length: %d\n", mdp.out.payload_length);
    return 1;
  }
  
  unsigned char plain[mdp.out.payload_length];
  unsigned long long plain_len=0;
  unsigned char *sas_public=&mdp.out.payload[1];
  unsigned char *compactsignature = &mdp.out.payload[1+SAS_SIZE];
  int siglen=SID_SIZE+crypto_sign_edwards25519sha512batch_BYTES;
  unsigned char signature[siglen];
  
  /* reconstitute signed SID for verification */
  bcopy(&compactsignature[0],&signature[0],64);
  bcopy(&mdp.out.src.sid[0],&signature[64],SID_SIZE);
  
  int r=crypto_sign_edwards25519sha512batch_open(plain,&plain_len,
						 signature,siglen,
						 sas_public);
  if (r) {
    printf("SID:SAS mapping verification signature does not verify\n");
    return 1;
  }
  /* These next two tests should never be able to fail, but let's just check anyway. */
  if (plain_len != SID_SIZE) {
    printf("SID:SAS mapping signed block is wrong length\n");
    return 1;
  }
  if (memcmp(plain, mdp.out.src.sid, SID_SIZE) != 0) {
    printf("SID:SAS mapping signed block is for wrong SID\n");
    return 1;
  }
  
  bcopy(sas_public, subscriber->sas_public, SAS_SIZE);
  subscriber->sas_valid=1;
  subscriber->sas_last_request=now;
  return 0;
}

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

  if (!sid || !msg || !sig) {
    print_usage();
    return 1;
  }

  int msg_length = strlen(msg);
  
  unsigned char bin_sig[SIGNATURE_BYTES];
  int valid_sig = fromhexstr(bin_sig,sig,SIGNATURE_BYTES); // convert signature from hex to binary
  
  if (strlen(sig) != 2*SIGNATURE_BYTES || valid_sig) {
    fprintf(stderr, "Invalid signature\n");
    return 1;
  }
  if (!str_is_subscriber_id(sid)) {
    fprintf(stderr,"Invalid SID\n");
    return 1;
  }

  unsigned char combined_msg[msg_length + SIGNATURE_BYTES];
  memcpy(combined_msg,msg,msg_length);
  memcpy(combined_msg + msg_length,bin_sig,SIGNATURE_BYTES); // append signature to end of message
  int combined_msg_length = msg_length + SIGNATURE_BYTES;

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

  struct subscriber *src_sub = find_subscriber(packedSid, SID_SIZE, 1); // get Serval identity described by given SID

  if (!src_sub) {
    fprintf(stderr, "Failed to fetch Serval subscriber\n");
    return 1;
  }
  
  if (keyring_send_sas_request_client(src_sub)) { // send MDP request for SAS public key of given SID
      printf("SAS request failed\n");
      return 1;
  }
  
  if (!src_sub->sas_valid) {
    fprintf(stderr, "Could not validate the signing key!\n");
    return 1;
  }
  
  int verdict = crypto_verify_message(src_sub, combined_msg, &combined_msg_length);
  
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
