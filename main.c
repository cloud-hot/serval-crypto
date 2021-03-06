#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <getopt.h>

#ifdef USESYSLOG
#include <syslog.h>
#endif

#include "serval-crypto.h"

enum {
  SIGN = 0,
  VERIFY = 1
};

static int command = -1;

void print_usage() {
  printf("serval-crypto (Serval Crypto) 3.0\n"
    "Usage: serval-crypto [--sign|--verify] [-m MESSAGE] [-i SID] [-s SIGNATURE]\n"
    "             [--message=MESSAGE] [--sid=SID] [--signature=SIGNATURE] [--help]\n\n"
    "Serval-crypto utilizes Serval's crypto API to:\n"
    "      * Sign any arbitrary text using a Serval key. If no Serval key ID (SID) is given,\n"
    "             a new key will be created on the default Serval keyring.\n"
    "      * Verify any arbitrary text, a signature, and a Serval key ID (SID), and will\n"
    "             determine if the signature is valid.\n\n"
    "Commands:\n\n"
    "      --sign                    Sign a message with a Serval key\n"
    "      --verify                  Verify a signed message with a Serval key\n\n"
    "Options:\n\n"
    "  -m, --message                 Message to sign or verify (not including signature)\n"
    "  -i, --sid                     Serval ID (SID) used to sign or verify. If a SID is not provided\n"
    "                                     when signing a message, a new SID is created.\n"
    "  -s, --signature               Signature of message to verify\n"
    "  -k, --keyring                 Keyring file (When verifying message, there must be a running\n"
    "                                     servald instance using this keyring)\n\n");
}

int main ( int argc, char *argv[] ) {
  unsigned char *msg = NULL;
  char *sid = NULL, *sig = NULL, *keyringName = NULL;
  int c, need_cleanup = 0, verdict = -1, msg_len = 0;
  
  while (1) {
    static struct option long_options[] = {
      {"sign",		no_argument, &command, SIGN},
      {"verify",	no_argument, &command, VERIFY},
      {"help",		no_argument, 0, 'h'},
      
      {"keyring",	required_argument, 0, 'k'},
      {"message",	required_argument, 0, 'm'},
      {"sid",		required_argument, 0, 'i'},
      {"signature",	required_argument, 0, 's'},
      {0,0,0,0}
    };
    
    int op_index = 0;
    c = getopt_long(argc,argv,"k:m:i:s:", long_options, &op_index);
    
    if (c == -1)
      break;
    
    switch (c) {
      case 0:
	break;
      case 'k':
	keyringName = optarg;
	break;
      case 'm':
	msg = (unsigned char*)optarg;
	break;
      case 'i':
	sid = optarg;
	break;
      case 's':
	sig = optarg;
	break;
      case 'h':
	print_usage();
	return 0;
      default:
	print_usage();
	return 1;
    }
  }
  
  if (command == -1 ||
      (command == SIGN && sig) ||
      (command == VERIFY && (!sig || !sid))) {
    print_usage();
    return 1;
  }
  
  if (!msg) {
    get_msg((char **)&msg);
    need_cleanup = 1;
  }
  msg_len = strlen(msg);
  
  if (command == SIGN) {
    verdict = serval_sign(sid,sid ? strlen(sid) : 0,
		     msg,msg_len,
		     NULL,0,
		     keyringName,keyringName ? strlen(keyringName) : 0);
  } else { // VERIFY
    verdict = serval_verify(sid,strlen(sid),
		     msg,msg_len,
		     sig,strlen(sig),
		     keyringName,keyringName ? strlen(keyringName) : 0);
  }
  
  if (need_cleanup) free(msg);
  
  return verdict;
}
