#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include "state.h"
#include "out_channel.h"
#include "in_channel.h"

int in_data (ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int fwlen;

    fprintf(stdout, "in_data callback called with %d bytes (stderr %d)\n", len, is_stderr);

    // Forward data to out channel
    if (is_stderr) {
        fwlen = ssh_channel_write_stderr(state->out_channel, data, len);
    } else {
        fwlen = ssh_channel_write(state->out_channel, data, len);
    }

    fprintf(stdout, "in_data callback wrote %d bytes\n", fwlen);

    return fwlen;
}

void in_eof (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_eof callback called\n");

    // Forward eof to out channel
    ssh_channel_send_eof(state->out_channel);
}

void in_close (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_close callback called\n");

    // Close out channel
    destroy_out_channel(state);
}

void in_signal (ssh_session session, ssh_channel channel, const char *signal, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_signal callback called with signal %s\n", signal);

    // Forward to out channel
    ssh_channel_request_send_signal(state->out_channel, signal);
}

void in_exit_status (ssh_session session, ssh_channel channel, int exit_status, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_exit_status callback called with status %d\n", exit_status);

    // Forward to out channel
    ssh_channel_request_send_exit_status(state->out_channel, exit_status);
}

void in_exit_signal (ssh_session session, ssh_channel channel, const char *signal, int core, const char *errmsg,
    const char *lang, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_exit_signal callback called with signal %s, core %d, error %s, lang %s\n",
        signal, core, errmsg, lang);

    // Forward to out channel
    ssh_channel_request_send_exit_signal(state->out_channel, signal, core, errmsg, lang);
}

int in_pty_request (ssh_session session, ssh_channel channel, const char *term, int width, int height,
    int pxwidth, int pxheight, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = -1;

    fprintf(stdout, "in_pty_request_callback callback called with term %s, char dim %dx%d, px dim %dx%d\n",
        term, width, height, pxwidth, pxheight);

    if (ssh_channel_request_pty_size(state->out_channel, term, width, height) == SSH_OK){
        rc = 0;
    }

    fprintf(stdout, "in_pty_window_change returning %d\n", rc);

    return rc;
}

int in_shell_request (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = 1;

    fprintf(stdout, "in_shell_request callback called\n");

    if (ssh_channel_request_shell(state->out_channel) == SSH_OK) {
        rc = 0;
    }

    fprintf(stdout, "in_shell_request returning %d\n", rc);

    return rc;
}

void in_auth_agent_req (ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_auth_agent_req callback called\n");

    // Forward to out channel
    ssh_channel_request_auth_agent(state->out_channel);
}

void in_x11_req (ssh_session session, ssh_channel channel, int single_connection, const char *auth_protocol,
    const char *auth_cookie, uint32_t screen_number, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;

    fprintf(stdout, "in_x11_req callback called, single_connection %d, auth protocol %s, auth cookie %s, screen %d\n",
        single_connection, auth_protocol, auth_cookie, screen_number);

    // Forward to out channel
    ssh_channel_request_x11(state->out_channel, single_connection, auth_protocol, auth_cookie, screen_number);
}

int in_pty_window_change (ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pxheight,
    void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = -1;

    fprintf(stdout, "in_pty_window_change callback called with char dim %dx%d, px dim %dx%d\n",
        width, height, pxwidth, pxheight);

    if (ssh_channel_change_pty_size (state->out_channel, width, height) == SSH_OK){
        rc = 0;
    }

    fprintf(stdout, "in_pty_window_change callback returning %d\n", rc);

    return rc;
}

int in_exec_request (ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = 1;

    fprintf(stdout, "in_exec_request callback called, command %s\n", command);

    // Forward to out channel
    if (ssh_channel_request_exec(state->out_channel, command) ==  SSH_OK) {
        rc = 0;
    }

    return rc;
}

int in_env_request (ssh_session session, ssh_channel channel, const char *env_name, const char *env_value, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = 1;

    fprintf(stdout, "in_env_request callback called, %s = '%s'\n", env_name, env_value);

    if (ssh_channel_request_env(state->out_channel, env_name, env_value) == SSH_OK) {
        rc = 0;
    }

    fprintf(stdout, "in_env_request callback returning %d\n", rc);

    return rc;
}

int in_subsystem_request (ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
    (void)session;
    (void)channel;

    stateptr state = (stateptr) userdata;
    int rc = 1;

    fprintf(stdout, "in_subsystem_request callback called for %s\n", subsystem);

    // Forward to out channel
    if (ssh_channel_request_subsystem(state->out_channel, subsystem) == SSH_OK) {
        rc = 0;
    }

    fprintf(stdout, "in_subsystem_request callback returning %d\n", rc);

    return rc;
}

#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 10, 0)

int in_write_wontblock (ssh_session session, ssh_channel channel, uint32_t bytes, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "in_write_wontblock callback called with bytes = %d\n", bytes);

    return 0;
}

#else

int in_write_wontblock (ssh_session session, ssh_channel channel, size_t bytes, void *userdata)
{
    (void)session;
    (void)channel;
    (void)userdata;

    fprintf(stdout, "in_write_wontblock callback called with bytes = %ld\n", bytes);

    return 0;
}

#endif

struct ssh_channel_callbacks_struct in_channel_callbacks = {
    .channel_data_function = in_data,
    .channel_eof_function = in_eof,
    .channel_close_function = in_close,
    .channel_signal_function = in_signal,
    .channel_exit_status_function = in_exit_status,
    .channel_exit_signal_function = in_exit_signal,
    .channel_pty_request_function = in_pty_request,
    .channel_shell_request_function = in_shell_request,
    .channel_auth_agent_req_function = in_auth_agent_req,
    .channel_x11_req_function = in_x11_req,
    .channel_pty_window_change_function = in_pty_window_change,
    .channel_exec_request_function = in_exec_request,
    .channel_env_request_function = in_env_request,
    .channel_subsystem_request_function = in_subsystem_request,
    .channel_write_wontblock_function = in_write_wontblock
};

ssh_channel create_in_channel(stateptr state)
{
    ssh_channel channel = NULL;

    // Initialise the callbacks struct
    ssh_callbacks_init(&in_channel_callbacks);
    in_channel_callbacks.userdata = state;

    // Create the new channel
    channel = ssh_channel_new(state->in_session);
    if (channel == NULL) {
        fprintf(stderr, "Failed to create inbound channel\n");

    } else {
        // Set callbacks
        ssh_set_channel_callbacks(channel, &in_channel_callbacks);

        // Set channel in state
        state->in_channel = channel;

    }

    return channel;
}

void destroy_in_channel(stateptr state)
{
    if (state->in_channel) {
        ssh_channel_close(state->in_channel);
        ssh_channel_free(state->in_channel);
        state->in_channel = NULL;

        if (state->out_channel == NULL) {
            state->finished = 1;
        }
    }
}
