#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include "state.h"
#include "in_channel.h"
#include "out_channel.h"

void poll_loop(stateptr state);

void dump_auth_methods(int methods)
{
    if (methods & SSH_AUTH_METHOD_NONE) {
        fprintf(stdout, " SSH_AUTH_METHOD_NONE");
        methods &= ~SSH_AUTH_METHOD_NONE;
    }
    if (methods & SSH_AUTH_METHOD_PASSWORD) {
        fprintf(stdout, " SSH_AUTH_METHOD_PASSWORD");
        methods &= ~SSH_AUTH_METHOD_PASSWORD;
    }
    if (methods & SSH_AUTH_METHOD_PUBLICKEY) {
        fprintf(stdout, " SSH_AUTH_METHOD_PUBLICKEY");
        methods &= ~SSH_AUTH_METHOD_PUBLICKEY;
    }
    if (methods & SSH_AUTH_METHOD_HOSTBASED) {
        fprintf(stdout, " SSH_AUTH_METHOD_HOSTBASED");
        methods &= ~SSH_AUTH_METHOD_HOSTBASED;
    }
    if (methods & SSH_AUTH_METHOD_INTERACTIVE) {
        fprintf(stdout, " SSH_AUTH_METHOD_INTERACTIVE");
        methods &= ~SSH_AUTH_METHOD_INTERACTIVE;
    }
    if (methods & SSH_AUTH_METHOD_GSSAPI_MIC) {
        fprintf(stdout, " SSH_AUTH_METHOD_GSSAPI_MIC");
        methods &= ~SSH_AUTH_METHOD_GSSAPI_MIC;
    }

    if (methods != 0) {
        fprintf(stdout, " + 0x%x", methods);
    }
}

char *auth_result(int auth_int)
{
    char *result;

    switch(auth_int){
    case SSH_AUTH_SUCCESS:
        result = "SSH_AUTH_SUCCESS";
        break;
    case SSH_AUTH_DENIED:
        result = "SSH_AUTH_DENIED";
        break;
    case SSH_AUTH_PARTIAL:
        result = "SSH_AUTH_PARTIAL";
        break;
    case SSH_AUTH_INFO:
        result = "SSH_AUTH_INFO";
        break;
    case SSH_AUTH_AGAIN:
        result = "SSH_AUTH_AGAIN";
        break;
    case SSH_AUTH_ERROR:
        result = "SSH_AUTH_ERROR";
        break;
    default:
        result = "[UNKNOWN]";
        break;
    }

    return result;
};

int in_auth (const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
    (void)buf;
    (void)userdata;

    fprintf(stdout, "in_auth callback called with prompt %s, buf len %ld, echo %d, verify %d\n",
        prompt, len, echo, verify);

    return SSH_ERROR;
}

void in_global_request (ssh_session session, ssh_message message, void *userdata)
{
    (void)session;
    (void)message;
    (void)userdata;

    fprintf(stdout, "in_global_request callback called (TODO)\n");

    // TODO
}

ssh_channel in_channel_open_request_x11 (ssh_session session, const char * originator_address, int originator_port, void *userdata)
{
    (void)session;
    (void)userdata;

    fprintf(stdout, "in_open_request_x11 callback called with originator address %s, port %d (TODO)\n",
        originator_address, originator_port);

    // TODO
    return NULL;
}

ssh_channel in_channel_open_request_auth_agent (ssh_session session, void *userdata)
{
    (void)session;
    (void)userdata;

    fprintf(stdout, "in_channel_open_request_auth_agent callback called (TODO)\n");

    // TODO
    return NULL;
}

int out_auth (const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
    (void)buf;
    (void)userdata;

    fprintf(stdout, "out_auth callback called with prompt %s, buf len %ld, echo %d, verify %d\n",
        prompt, len, echo, verify);

    return SSH_ERROR;
}

void out_global_request (ssh_session session, ssh_message message, void *userdata)
{
    (void)session;
    (void)message;
    (void)userdata;

    fprintf(stdout, "out_global_request callback called (TODO)\n");

    // TODO
}

ssh_channel out_channel_open_request_x11 (ssh_session session, const char * originator_address, int originator_port, void *userdata)
{
    (void)session;
    (void)userdata;

    fprintf(stdout, "out_open_request_x11 callback called with originator address %s, port %d (TODO)\n",
        originator_address, originator_port);

    // TODO
    return NULL;
}

ssh_channel out_channel_open_request_auth_agent (ssh_session session, void *userdata)
{
    (void)session;
    (void)userdata;

    fprintf(stdout, "out_channel_open_request_auth_agent callback called (TODO)\n");

    // TODO
    return NULL;
}

int auth_password(ssh_session session, const char *user, const char *password, void *userdata)
{
    (void)session;

    stateptr state = (stateptr) userdata;
    int result;

    fprintf(stdout, "auth_password callback called with user %s, password %s\n", user, password);

    result = ssh_userauth_password(state->out_session, user, password);

    fprintf(stdout, "auth_password callback returning %s\n", auth_result(result));

    return result;
}

int auth_none(ssh_session session, const char *user, void *userdata)
{
    (void)session;

    stateptr state = (stateptr) userdata;
    int result;
    int auth_methods;

    fprintf(stdout, "auth_none callback called with user %s\n", user);

    result = ssh_userauth_none(state->out_session, user);

    if (result != SSH_AUTH_SUCCESS) {
        // Get list of valid auth methods
        auth_methods = ssh_userauth_list(state->out_session, NULL);

        // Dump them out
        fprintf(stdout, "Returned auth_methods:");
        dump_auth_methods(auth_methods);
        fprintf(stdout, "\n");

        // Only offer PUBLICKEY if we have key files configured
        if (auth_methods & SSH_AUTH_METHOD_PUBLICKEY && (!state->pub_key_file || !state->priv_key_file)) {
            fprintf(stderr, "Removing SSH_AUTH_METHOD_PUBLICKEY auth method because key files not specified\n");
            auth_methods &= ~SSH_AUTH_METHOD_PUBLICKEY;
        }

        // Set auth methods in the inbound session
        ssh_set_auth_methods(state->in_session, auth_methods);
    }

    fprintf(stdout, "auth_none callback returning %s\n", auth_result(result));

    return result;
}

int auth_gssapi_mic(ssh_session session, const char *user, const char *principal, void *userdata)
{
    (void)session;
    (void)userdata;

    fprintf(stdout, "auth_gssapi_mic callback called with user %s, principal %s (TODO)\n", user, principal);

    // TODO
    return SSH_AUTH_DENIED;
}

int auth_pubkey(ssh_session session, const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata)
{
    (void)session;
    (void)pubkey;

    stateptr state = (stateptr) userdata;
    ssh_key pkey;
    int result = SSH_AUTH_DENIED;
    char *state_str = "[UNKNOWN]";

    switch(signature_state){
    case SSH_PUBLICKEY_STATE_NONE:
        state_str = "SSH_PUBLICKEY_STATE_NONE";
        break;
    case SSH_PUBLICKEY_STATE_VALID:
        state_str = "SSH_PUBLICKEY_STATE_VALID";
        break;
    }

    fprintf(stdout, "auth_pubkey callback called with user %s, signature state %s\n", user, state_str);

    switch(signature_state){
    case SSH_PUBLICKEY_STATE_NONE:
        if (state->pub_key_file && state->priv_key_file) {
            if (ssh_pki_import_pubkey_file(state->pub_key_file, &pkey) != SSH_OK){
                fprintf(stderr, "Failed to load public key %s\n", state->pub_key_file);
                result = SSH_AUTH_DENIED;
            } else {
                result = ssh_userauth_try_publickey(state->out_session, user, pkey);
                ssh_key_free(pkey);
            }
        } else {
            fprintf(stderr, "Public and private key files must be specified for outbound connection\n");
        }
        break;

    case SSH_PUBLICKEY_STATE_VALID:
        if (state->pub_key_file && state->priv_key_file) {
            if (ssh_pki_import_privkey_file(state->priv_key_file, NULL, NULL, NULL, &pkey) != SSH_OK){
                fprintf(stderr, "Failed to load private key %s\n", state->priv_key_file);
                result = SSH_AUTH_DENIED;
            } else {
                result = ssh_userauth_publickey(state->out_session, user, pkey);
            }
        } else {
            fprintf(stderr, "Public and private key files must be specified for outbound connection\n");
        }
        break;

    }

    fprintf(stdout, "auth_pubkey callback returning %s\n", auth_result(result));

    return result;
}

int service_request(ssh_session session, const char *service, void *userdata)
{
    (void)session;

    stateptr state = (stateptr) userdata;
    int rc = -1;

    fprintf(stdout, "service_request callback called with service %s\n", service);

    if (ssh_service_request(state->out_session, service) == SSH_OK) {
        rc = 0;
    }

    fprintf(stdout, "service_request callback returnng %d\n", rc);

    return rc;
}

ssh_channel channel_open_request_session(ssh_session session, void *userdata)
{
    (void)session;

    stateptr state = (stateptr) userdata;
    ssh_channel result = NULL;

    fprintf(stdout, "open_request_session callback called\n");

    if (create_out_channel(state)) {
        if (create_in_channel(state)) {
            result = state->in_channel;
        } else {
            destroy_out_channel(state);
        }
    }

    return result;
}

ssh_string gssapi_select_oid(ssh_session session, const char *user, int n_oid, ssh_string *oids, void *userdata)
{
    (void)session;
    (void)userdata;
    (void)oids;

    fprintf(stdout, "gssapi_select_oid callback called, user %s, number of OIDs = %d (TODO)\n", user, n_oid);

    // TODO
    return NULL;
}

int gssapi_accept_sec_ctx(ssh_session session, ssh_string input_token, ssh_string *output_token, void *userdata)
{
    (void)session;
    (void)input_token;
    (void)output_token;
    (void)userdata;

    fprintf(stdout, "gssapi_accept_sec_ctx_callback callback called (TODO)\n");

    // TODO
    return SSH_ERROR;
}

int gssapi_verify_mic(ssh_session session, ssh_string mic, void *mic_buffer, size_t mic_buffer_size, void *userdata)
{
    (void)session;
    (void)mic;
    (void)mic_buffer;
    (void)userdata;

    fprintf(stdout, "gssapi_verify_mic callback called, mic buffer size = %ld (TODO)\n", mic_buffer_size);

    // TODO
    return SSH_ERROR;
}

void dump_session(stateptr state)
{
    struct ssh_server_callbacks_struct server_callbacks = {
        .auth_password_function = &auth_password,
        .auth_none_function = &auth_none,
        .auth_gssapi_mic_function = &auth_gssapi_mic,
        .auth_pubkey_function = &auth_pubkey,
        .service_request_function = &service_request,
        .channel_open_request_session_function = &channel_open_request_session,
        .gssapi_select_oid_function = &gssapi_select_oid,
        .gssapi_accept_sec_ctx_function = &gssapi_accept_sec_ctx,
        .userdata = state,
        .gssapi_verify_mic_function = &gssapi_verify_mic,
    };

    struct ssh_callbacks_struct in_callbacks = {
        .auth_function = &in_auth,
        .global_request_function = &in_global_request,
        .channel_open_request_x11_function = &in_channel_open_request_x11,
        .channel_open_request_auth_agent_function = &in_channel_open_request_auth_agent
    };

    struct ssh_callbacks_struct out_callbacks = {
        .auth_function = &out_auth,
        .global_request_function = &out_global_request,
        .channel_open_request_x11_function = &out_channel_open_request_x11,
        .channel_open_request_auth_agent_function = &out_channel_open_request_auth_agent
    };

    // Set up in session callbacks
    ssh_callbacks_init(&in_callbacks);
    ssh_callbacks_init(&out_callbacks);
    ssh_callbacks_init(&server_callbacks);

    ssh_set_callbacks(state->in_session, &in_callbacks);
    ssh_set_callbacks(state->out_session, &out_callbacks);
    ssh_set_server_callbacks(state->in_session, &server_callbacks);

    // Enter poll loop
    poll_loop(state);

    // Clear in session callbacks
    ssh_set_callbacks(state->in_session, NULL);
    ssh_set_callbacks(state->out_session, NULL);
    ssh_set_server_callbacks(state->in_session, NULL);

    return;
}

void poll_loop(stateptr state)
{
    do {
        // Create the event
        state->event = ssh_event_new();
        if (state->event == NULL) {
            fprintf(stderr, "Could not create polling context\n");
            break;
        }

        // Add sessions to the event
        ssh_set_blocking(state->in_session, 0);

        if (ssh_event_add_session(state->event, state->in_session) != SSH_OK) {
            fprintf(stderr, "Error adding in session to polling context\n");
            break;
        }

        if (ssh_event_add_session(state->event, state->out_session) != SSH_OK) {
            fprintf(stderr, "Error adding out session to polling context\n");
            break;
        }

        // Poll for events
        fprintf(stdout, "Entering poll loop...\n");

        while (!state->finished) {
            if (ssh_event_dopoll(state->event, 100) == SSH_ERROR) {
                fprintf(stderr, "ssh_event_dopoll error: %s\n", ssh_get_error(state->in_session));
                break;
            }
        }

        fprintf(stdout, "Exited poll loop\n");
    } while(0);

    if (state->event) {
        // Destroy event
        ssh_event_remove_session(state->event, state->in_session);
        ssh_event_remove_session(state->event, state->out_session);
        ssh_event_free(state->event);
        state->event = NULL;
    }
}