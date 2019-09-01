#include <libssh/libssh.h>

#include "state.h"

ssh_channel create_in_channel(stateptr state);
void destroy_in_channel(stateptr state);
