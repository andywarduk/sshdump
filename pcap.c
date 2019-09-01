#include <stdio.h>
#include <libssh/libssh.h>

const char *pcap_file = "debug.server.pcap";
ssh_pcap_file pcap;

void set_pcap(ssh_session session){
    if(!pcap_file) return;

    pcap = ssh_pcap_file_new();

    if(ssh_pcap_file_open(pcap, pcap_file) == SSH_ERROR){
        fprintf(stderr, "Error opening pcap file %s\n", pcap_file);
        ssh_pcap_file_free(pcap);
        pcap=NULL;
        return;
    }

    ssh_set_pcap_file(session,pcap);
}

void cleanup_pcap(){
    ssh_pcap_file_free(pcap);
    pcap = NULL;
}
