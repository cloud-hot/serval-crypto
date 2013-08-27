#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <argp.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif

#define HAVE_ARPA_INET_H

#include <serval.h>
#include <overlay_address.h>
#include <crypto.h>
#include <str.h>
#include <assert.h>

#include "serval-crypto.h"

#define KEYRING_PIN NULL
#define MAX_SAS_VALIDATION_ATTEMPTS 10

static struct arguments {
  unsigned char *sid;
  unsigned char *sig;
  unsigned char *msg;
  int num_args;
} arguments;

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

int verify(const char *sid, 
	   size_t sid_len,
	   const char *msg,
	   size_t msg_len,
	   const char *sig,
	   size_t sig_len) {
  
  assert(sid_len == 2*SID_SIZE);
  assert(sig_len == 2*SIGNATURE_BYTES);
  
  unsigned char bin_sig[SIGNATURE_BYTES];
  int valid_sig = fromhexstr(bin_sig,sig,SIGNATURE_BYTES); // convert signature from hex to binary
  
  if (valid_sig) {
    fprintf(stderr, "Invalid signature\n");
    return 1;
  }
  if (!str_is_subscriber_id(sid)) {
    fprintf(stderr,"Invalid SID\n");
    return 1;
  }
  
  unsigned char combined_msg[msg_len + SIGNATURE_BYTES];
  memcpy(combined_msg,msg,msg_len);
  memcpy(combined_msg + msg_len,bin_sig,SIGNATURE_BYTES); // append signature to end of message
  int combined_msg_length = msg_len + SIGNATURE_BYTES;
  
  char keyringFile[1024];
  FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"); // this should target default Serval keyring
  keyring = keyring_open(keyringFile);
  if (!keyring) {
    fprintf(stderr, "Failed to open Serval keyring\n");
    return 1;
  }
  int num_identities = keyring_enter_pin(keyring, KEYRING_PIN); // unlocks Serval keyring for using identities (also initializes global default identity my_subscriber)
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
  
  DEBUG("Message to verify:");
  DEBUG("\n%s",msg);
  
  int verdict = crypto_verify_message(src_sub, combined_msg, &combined_msg_length);
  
  if (!verdict) {
    printf("Message verified!\n");
  }
  else {
    printf("Message NOT verified\n");
  }
  
  keyring_free(keyring);
   
  return verdict;
  
}

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  
  switch (key) {
    case 'i':
      arguments->sid = arg;
      arguments->num_args++;
      break;
    case 'm':
      arguments->msg = arg;
      arguments->num_args++;
      break;
    case 's':
      arguments->sig = arg;
      arguments->num_args++;
      break;
    case ARGP_KEY_END:
      if (arguments->num_args != 3)
	argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

#ifndef SHARED
int main ( int argc, char *argv[] ) {

  int need_cleanup = 0;
  
  const char *argp_program_version = "2.1";
  static char doc[] = "Serval Verify";
  static struct argp_option options[] = {
    {"sid", 'i', "SID", 0, "Serval ID (SID) used to sign the message" },
    {"msg", 'm', "MESSAGE", 0, "Message that was signed (does not include signature)" },
    {"sig", 's', "SIGNATURE", 0, "Signature of the message, signed by the given SID" },
    { 0 }
  };
  
  /* Set defaults */
  arguments.msg = NULL;
  arguments.sid = NULL;
  arguments.sig = NULL;
  arguments.num_args = 0;
  
  static struct argp argp = { options, parse_opt, NULL, doc };
  
  argp_parse (&argp, argc, argv, 0, 0, &arguments);
  
  if (!arguments.msg) {
    get_msg(&(arguments.msg));
    need_cleanup = 1;
  }

  int verdict = verify(arguments.sid,strlen(arguments.sid),
		       arguments.msg,strlen(arguments.msg),
		       arguments.sig,strlen(arguments.sig));
  if (need_cleanup) free(arguments.msg);
  return verdict;

}
#endif
