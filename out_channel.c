#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include "state.h"
#include "out_channel.h"
#include "in_channel.h"

int out_data (ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int fwlen;

    fprintf(stdout, "out_data callback called with %d bytes (stderr %d)\n", len, is_stderr);

    // Forward data to in channel
    if (is_stderr) {
        fwlen = ssh_channel_write_stderr(state->in_channel, data, len);
    } else {
        fwlen = ssh_channel_write(state->in_channel, data, len);
    }

    fprintf(stdout, "out_data callback wrote %d bytes\n", fwlen);

    return fwlen;
}

void out_eof (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "out_eof callback called\n");

    // Forward eof to in channel
    ssh_channel_send_eof(state->in_channel);
}

void out_close (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "out_close callback called\n");

    // Close in channel
    destroy_in_channel(state);
}

void out_signal (ssh_session session, ssh_channel channel, const char *signal, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_signal callback called with signal %s (UNEXPECTED)\n", signal);
}

void out_exit_status (ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_exit_status callback called with status %d (UNEXPECTED)\n", exit_status);
}

void out_exit_signal (ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg,
    const char *lang, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_exit_signal callback called with signal %s, core %d, error %s, lang %s (UNEXPECTED)\n",
        signal, core, errmsg, lang);
}

int out_pty_request (ssh_session session, ssh_channel channel, const char *term, int width, int height,
    int pxwidth, int pxheight, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_pty_request_callback callback called with term %s, char dim %dx%d, px dim %dx%d (UNEXPECTED)\n",
        term, width, height, pxwidth, pxheight);

    return -1;
}

int out_shell_request (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_shell_request callback called (UNEXPECTED)\n");

    return 1;
}

void out_auth_agent_req (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_auth_agent_req callback called (UNEXPECTED)\n");
}

void out_x11_req (ssh_session session, ssh_channel channel, int single_connection, const char *auth_protocol,
    const char *auth_cookie, uint32_t screen_number, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_x11_req callback called, single_connection %d, auth protocol %s, auth cookie %s, screen %d (UNEXPECTED)\n",
        single_connection, auth_protocol, auth_cookie, screen_number);
}

int out_pty_window_change (ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pxheight,
    void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_pty_window_change callback called with char dim %dx%d, px dim %dx%d (UNEXPECTED)\n",
        width, height, pxwidth, pxheight);

    return -1;
}

int out_exec_request (ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_exec_request callback called, command %s (UNEXPECTED)\n", command);

    return 1;
}

int out_env_request (ssh_session session, ssh_channel channel, const char *env_name, const char *env_value, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_env_request callback called, %s = '%s' (UNEXPECTED)\n", env_name, env_value);

    return 1;
}

int out_subsystem_request (ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_subsystem_request callback called for %s (UNEXPECTED)\n", subsystem);

    return 1;
}

int out_write_wontblock (ssh_session session, ssh_channel channel, size_t bytes, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "out_write_wontblock callback called with bytes = %ld\n", bytes);

    return 0;
}

struct ssh_channel_callbacks_struct out_channel_callbacks = {
    .channel_data_function = out_data,
    .channel_eof_function = out_eof,
    .channel_close_function = out_close,
    .channel_signal_function = out_signal,
    .channel_exit_status_function = out_exit_status,
    .channel_exit_signal_function = out_exit_signal,
    .channel_pty_request_function = out_pty_request,
    .channel_shell_request_function = out_shell_request,
    .channel_auth_agent_req_function = out_auth_agent_req,
    .channel_x11_req_function = out_x11_req,
    .channel_pty_window_change_function = out_pty_window_change,
    .channel_exec_request_function = out_exec_request,
    .channel_env_request_function = out_env_request,
    .channel_subsystem_request_function = out_subsystem_request,
    .channel_write_wontblock_function = out_write_wontblock
};

ssh_channel create_out_channel(stateptr state)
{
    int ok = 0;

    // Initialise the callbacks struct
    ssh_callbacks_init(&out_channel_callbacks);
    out_channel_callbacks.userdata = state;

    // Already have one?
    if (state->out_channel) {
        fprintf(stderr, "create_out_channel: outbound channel already active\n");

    } else {
        // Create the channel
        state->out_channel = ssh_channel_new(state->out_session);

        if (state->out_channel == NULL) {
            fprintf(stderr, "create_out_channel: unable to create outbound channel\n");

        } else {
            // Set callbacks
            ssh_set_channel_callbacks(state->out_channel, &out_channel_callbacks);

            // Open the session
            if (ssh_channel_open_session(state->out_channel) != SSH_OK){
                fprintf(stderr, "create_out_channel: outbound channel could not be established\n");

            } else {
                // Finished successfully
                ok = 1;

            }
        }
    }

    if (!ok) {
        // Make sure out channel is destroyed
        destroy_out_channel(state);
    }

    return state->out_channel;
}

void destroy_out_channel(stateptr state)
{
    if (state->out_channel) {
        ssh_channel_close(state->out_channel);
        ssh_channel_free(state->out_channel);
        state->out_channel = NULL;

        if (state->in_channel == NULL) {
            state->finished = 1;
        }
    }
}
