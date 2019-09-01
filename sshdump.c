#include <stdio.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "state.h"
#include "args.h"
#include "pcap.h"
#include "session.h"

int open_outbound_connection(struct state_struct *state);

struct state_struct state = {
    .log_level = SSH_LOG_NONE,
    .in_port = 9000,
    .out_host = "localhost",
    .out_port = 22,
    .finished = 0
};

int main(int argc, char **argv){
    int result = 1;
    ssh_bind sshbind;
    int r;

    do {
        // Parse command line arguments
        if(!parse_args(argc, argv, &state)) {
            break;
        }

        // Create new in_session
        state.in_session = ssh_new();
        if (state.in_session == NULL) {
            fprintf(stderr, "Unable to create new session\n");
            break;
        }

        // Start pcap capture on the in_session
        set_pcap(&state);

        // Create new bind
        sshbind = ssh_bind_new();
        if (sshbind == NULL) {
            fprintf(stderr, "Unable to create new bind\n");
            break;
        }

        // Set bind options
        if (state.dsa_key_file) {
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, state.dsa_key_file);
        }
        if (state.rsa_key_file) {
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, state.rsa_key_file);
        }
        if (state.ecdsa_key_file) {
            ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_ECDSAKEY, state.ecdsa_key_file);
        }
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &state.in_port);
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &state.log_level);

        // Start listening for incoming connection
        if(ssh_bind_listen(sshbind) < 0){
            fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
            break;
        }
        fprintf(stdout, "Listening on port %d\n", state.in_port);

        // Accept a connection
        r = ssh_bind_accept(sshbind, state.in_session);
        if (r == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: %s\n", ssh_get_error(sshbind));
            break;
        }
        fprintf(stdout, "Accepted a connection\n");

        // Open outbound session
        if (open_outbound_connection(&state) != 0) {
            break;
        }

        // Do key exchange
        fprintf(stdout, "Exchanging keys on inbound connection...\n");

        if (ssh_handle_key_exchange(state.in_session)) {
            fprintf(stderr, "ssh_handle_key_exchange errored: %s\n", ssh_get_error(state.in_session));
            break;
        }

        fprintf(stdout, "Keys exchanged\n");

        // Dump the in_session
        dump_session(&state);

        result = 0;
    } while(0);

    // Clean up
    if (state.in_session) {
        ssh_disconnect(state.in_session);
        ssh_free(state.in_session);
        state.in_session = NULL;
    }

    if (state.out_session) {
        ssh_disconnect(state.out_session);
        ssh_free(state.out_session);
        state.out_session = NULL;
    }

    if (sshbind) {
        ssh_bind_free(sshbind);
    }

    cleanup_pcap(&state);
    
    ssh_finalize();

    return result;
}

int open_outbound_connection(struct state_struct *state)
{
    int rc;

    state->out_session = ssh_new();
    if (state->out_session == NULL) {
        fprintf(stderr, "Unable to create new session\n");
        return -1;
    }

    ssh_options_set(state->out_session, SSH_OPTIONS_LOG_VERBOSITY, &state->log_level);
    ssh_options_set(state->out_session, SSH_OPTIONS_HOST, state->out_host);
    ssh_options_set(state->out_session, SSH_OPTIONS_PORT, &state->out_port);

    // Connect to server
    fprintf(stdout, "Connecting to %s:%d\n", state->out_host, state->out_port);

    rc = ssh_connect(state->out_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error making outbound connection: %s\n", ssh_get_error(state->out_session));
        return -1;
    }

    fprintf(stdout, "Connected to %s:%d\n", state->out_host, state->out_port);

    return 0;
}
