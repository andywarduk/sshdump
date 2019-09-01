#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libssh/libssh.h>

#include "state.h"

#define KEYS_FOLDER "./keys/"

static char *short_options = "l:p:o:vh:P:r:d:e:k:K:";

static struct option long_options[] = {
    {"loglevel",    required_argument, 0, 'l'},
    {"inport",      required_argument, 0, 'p'},
    {"pcap",        required_argument, 0, 'o'},
    {"verbose",     no_argument,       0, 'v'},
    {"host",        required_argument, 0, 'h'},
    {"outport",     required_argument, 0, 'P'},
    {"rsa",         required_argument, 0, 'r'},
    {"dsa",         required_argument, 0, 'd'},
    {"ecdsa",       required_argument, 0, 'e'},
    {"pubkey",      required_argument, 0, 'k'},
    {"privkey",     required_argument, 0, 'K'},
    {0, 0, 0, 0}
};

void usage(char **argv)
{
    fprintf(stdout, "Usage:\n");
    fprintf(stdout, "%s <args>\n", argv[0]);
    fprintf(stdout, "Where args are:\n");
    fprintf(stdout, " -l | --loglevel <num>     Set libssh log level (%d-%d)\n", SSH_LOG_WARNING, SSH_LOG_FUNCTIONS);
    fprintf(stdout, " -v | --verbose            Increase libssh log level\n");
    fprintf(stdout, " -p | --inport <num>       Set TCP/IP port to listen on, 1-65535. Default 9000\n");
    fprintf(stdout, " -o | --pcap <file>        Set packet capture file name. Defaults to none\n");
    fprintf(stdout, " -h | --host <name>        Set host to connect to. Defaults to 'localhost''\n");
    fprintf(stdout, " -P | --outport <num>      Set TCP/IP port to connect to, 1-65535. Default 22\n");
    fprintf(stdout, " -r | --rsa <file>         Set the RSA private key file to use for the inbound connection\n");
    fprintf(stdout, " -d | --dsa <file>         Set the DSA private key file to use for the inbound connection\n");
    fprintf(stdout, " -e | --ecdsa <file>       Set the ECDSA private key file to use for the inbound connection\n");
    fprintf(stdout, " -k | --pubkey <file>      Set the public key file to use for the outbound connection\n");
    fprintf(stdout, " -K | --privkey <file>     Set the private key file to use for the outbound connection\n");
}

int check_file(char *file)
{
    int rc;
    struct stat statbuf;

    do {
        // Try and stat the file
        rc = stat(file, &statbuf);
        if (rc != 0) break;

        // Make sure it's a regular file
        if (S_ISREG(statbuf.st_mode)) {
            rc = -1;
            break;
        }

        // Make sure we can read it
        rc = access(file, R_OK);
        if (rc != 0) break;
    } while (0);

    return rc;
}

char *check_file_or_null(char *file)
{
    if (check_file(file)) return file;
    return NULL;
}

int check_int_arg(char *arg, int *result, int low, int high)
{
    int rc = 1;
    long int longint;
    char *endptr;

    do {
        longint = strtol(arg, &endptr, 0);

        if (endptr == arg || *endptr != '\x0'){
            break;
        }

        if (longint < (long int) low || longint > (long int) high) {
            break;
        }

        *result = (int) longint;
        rc = 0;
    } while (0);

    return rc;
}

int parse_args(int argc, char **argv, stateptr state)
{
    int args_ok = 1;

    while (args_ok) {
        int opt = getopt_long(argc, argv, short_options, long_options, NULL);

        if (opt == -1) break;

        switch (opt){
        case 'l':
            // Log level
            if (!check_int_arg(optarg, &(state->log_level), SSH_LOG_WARNING, SSH_LOG_FUNCTIONS)) {
                fprintf(stderr, "Log level should be between %d and %d\n", SSH_LOG_WARNING, SSH_LOG_FUNCTIONS);
                args_ok = 0;
            }
            break;

        case 'v':
            // Increase log level
            if (state->log_level < SSH_LOG_FUNCTIONS) {
                ++state->log_level;
            }
            break;

        case 'p':
            // Listen port
            if (!check_int_arg(optarg, &(state->in_port), 1, 65535)) {
                fprintf(stderr, "Listen port should be an integer between 1 and 65535\n");
                args_ok = 0;
            }
            break;

        case 'o':
            // pcap file name
            state->pcap_file = optarg;
            break;

        case 'h':
            // Host to connect to
            state->out_host = optarg;
            break;

        case 'P':
            // Port to connect to
            if (!check_int_arg(optarg, &(state->out_port), 1, 65535)) {
                fprintf(stderr, "Outbound port should be an integer between 1 and 65535\n");
                args_ok = 0;
            }
            break;

        case 'r':
            // RSA private key file
            if (check_file(optarg)) {
                state->rsa_key_file = optarg;
            } else {
                fprintf(stderr, "File '%s' is not valid\n", optarg);
                args_ok = 0;
            }
            break;

        case 'd':
            // DSA private key file
            if (check_file(optarg)) {
                state->dsa_key_file = optarg;
            } else {
                fprintf(stderr, "File '%s' is not valid\n", optarg);
                args_ok = 0;
            }
            break;

        case 'e':
            // ECDSA private key file
            if (check_file(optarg)) {
                state->ecdsa_key_file = optarg;
            } else {
                fprintf(stderr, "File '%s' is not valid\n", optarg);
                args_ok = 0;
            }
            break;

        case 'k':
            // Public key file
            if (check_file(optarg)) {
                state->pub_key_file = optarg;
            } else {
                fprintf(stderr, "File '%s' is not valid\n", optarg);
                args_ok = 0;
            }
            break;

        case 'K':
            // Private key file
            if (check_file(optarg)) {
                state->priv_key_file = optarg;
            } else {
                fprintf(stderr, "File '%s' is not valid\n", optarg);
                args_ok = 0;
            }
            break;

        default:
            // Unrecognised
            usage(argv);
            args_ok = 0;
            break;

        }
    }

    while (args_ok) {
        args_ok = 0;

        if (!state->dsa_key_file && !state->rsa_key_file && !state->ecdsa_key_file) {
            // No key files given - default
            state->rsa_key_file = check_file_or_null(KEYS_FOLDER "ssh_host_rsa_key");
            state->dsa_key_file = check_file_or_null(KEYS_FOLDER "ssh_host_dsa_key");
            state->ecdsa_key_file = check_file_or_null(KEYS_FOLDER "ssh_host_ecdsa_key");
        }

        if ((!state->pub_key_file  && state->priv_key_file) || (state->pub_key_file && !state->priv_key_file)) {
            fprintf(stderr, "Public and private key files for outbound connection must be specified\n");
            break;
        }

        if (!state->pub_key_file && !state->priv_key_file) {
            // No key files specified for outbound connection - default
            state->pub_key_file = check_file_or_null(KEYS_FOLDER "ssh_rsa_key.pub");
            state->priv_key_file = check_file_or_null(KEYS_FOLDER "ssh_rsa_key");
        }

        if (!state->pub_key_file || !state->priv_key_file) {
            state->pub_key_file = NULL;
            state->priv_key_file = NULL;
        }

        args_ok = 1;
        break;
    }

    return args_ok;
}
