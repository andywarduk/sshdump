#include <libssh/libssh.h>

#include "state.h"

ssh_channel create_out_channel(stateptr state);
void destroy_out_channel(stateptr state);
