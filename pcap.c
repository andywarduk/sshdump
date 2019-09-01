#include <stdio.h>
#include <libssh/libssh.h>

#include "state.h"

void set_pcap(stateptr state){
    if(!state->pcap_file) return;

    state->pcap = ssh_pcap_file_new();

    if(ssh_pcap_file_open(state->pcap, state->pcap_file) == SSH_ERROR){
        fprintf(stderr, "Error opening pcap file %s\n", state->pcap_file);
        ssh_pcap_file_free(state->pcap);
        state->pcap = NULL;
        return;
    }

    ssh_set_pcap_file(state->in_session, state->pcap);
}

void cleanup_pcap(stateptr state){
    if (state->pcap) {
        ssh_pcap_file_free(state->pcap);
        state->pcap = NULL;
    }
}
