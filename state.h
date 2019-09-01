#include <libssh/libssh.h>

#ifndef STATE_H
#define STATE_H

struct state_struct {
    int finished;
    
    int log_level;

    int in_port;

    char *out_host;
    int out_port;

    char *pcap_file;
    ssh_pcap_file pcap;

    ssh_event event;
    ssh_session in_session;
    ssh_session out_session;
    ssh_channel in_channel;
    ssh_channel out_channel;

    char *rsa_key_file;     // Private RSA key used for inbound connections
    char *dsa_key_file;     // Private DSA key used for inbound connections
    char *ecdsa_key_file;   // Private ECDSA key used for inbound connections

    char *pub_key_file;     // Public key file used for outbound authentication
    char *priv_key_file;    // Private key file used for outbound authentication
};
typedef struct state_struct *stateptr;

#endif
