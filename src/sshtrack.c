#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <argp.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/sshtrack.h"
#include "../include/sshtrack.skel.h"

#define SSHD_PORT 22
#define MAX_JSON_LEN 708

char filename[NAME_MAX];

int get_sshd_uid() {
    struct passwd *pwd;
    char *username = "sshd";
    int uid;

    pwd = getpwnam(username);
    if (pwd == NULL) {
        fprintf(stderr, "Error: User %s not found.\n", username);
        exit(EXIT_FAILURE);
    }

    uid = pwd->pw_uid;
    return uid;
}

int get_sshd_pid() {
    FILE *fp;
    char pid_str[10];
    int pid = -1;

    fp = popen("pgrep sshd", "r");
    if (fp == NULL) {
        perror("popen failed");
        return -1;
    }

    ssize_t bytes_read = read(fileno(fp), pid_str, sizeof(pid_str) - 1);
    if (bytes_read != -1) {
        pid_str[bytes_read] = '\0';
        pid = atoi(pid_str);
    }

    pclose(fp);

    return pid;
}

char* null_non_ascii_ctrl(const char* str) {
    size_t len = strlen(str);
    char* result = (char*)malloc(len+1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if ((isascii(str[i]) != 0) && (iscntrl(str[i]) == 0)) {
            result[j] = str[i];
            j++;
        } else {
            free(result); // deallocate memory
            result = (char*)malloc(2); // allocate memory for "\0"
            result[0] = '\0'; // set the string to "\0"
            return result;
        }
    }
    result[j] = '\0';
    return result;
}

char* session_context_to_json(struct session_context_t* session, bool harmful) {
    char* json = (char*)malloc(MAX_JSON_LEN);  // Allocating a string of sufficient size
    struct in_addr addr;
    addr.s_addr = session->source_addr;

    sprintf(json, "{ \"session_cookie\": %u, "
                  "\"login_timestamp\": %llu, "
                  "\"uid\": %u, "
                  "\"init_pid\": %d, "
                  "\"source_addr\": \"%s\", "
                  "\"source_port\": %u, "
                  "\"last_comm\": "
                    "{ \"timestamp\": %llu, "
                    "\"command\": \"%s\","
                    "\"argv\": [",
                  session->session_cookie,
                  session->login_timestamp,
                  session->uid,
                  session->init_pid,
                  inet_ntoa(addr),
                  session->source_port,
                  session->last_comm.timestamp,
                  session->last_comm.command);

    for (int i = 0; i < 6; i++) {
        strcat(json, "\"");
        char *nulled = null_non_ascii_ctrl(session->last_comm.argv[i]);
        strcat(json, nulled);
        free(nulled);
        strcat(json, "\"");
        if (i < 5) {
            strcat(json, ", ");
        }
    }

    strcat(json, "], ");

    if (harmful){
        strcat(json,"\"suspect\": true } }");
    } else {
        strcat(json,"\"suspect\": false } }");
    }

    return json;
}

static int open_raw_sock(const char *name)
{
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "Failed to create raw socket\n");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_pkttype = PACKET_HOST;
    sll.sll_ifindex = if_nametoindex(name);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int check_suspect_bins(const char *command){

    char *suspect_bins = "suspect_bins";
    FILE* file = fopen(suspect_bins, "r");
    if (file == NULL) {
        printf("Unable to open the file %s\n",suspect_bins);
        return -1;
    }

    char line[TASK_COMM_LEN];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        int len = strcspn(command,"\0") ;
        if (strncmp(line,command,len) == 0){
            fclose(file);
            return 1;
        }

    }

    fclose(file);
    return 0;
}

int write_to_file(const char* string) {
    // Open the file in "append" mode to add the string to the end
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        return -1;
    }

    // Write the string to the file
    fprintf(file, "%s\n", string);

    // Close the file
    fclose(file);
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    /*if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;*/
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
            .rlim_cur	= RLIM_INFINITY,
            .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! Please execute as sudo.\n");
        exit(1);
    }
}

static int handle_session_start_event(void *ctx, void *data, size_t data_sz)
{
    struct session_context_t *session = data;
    char *json_str = session_context_to_json(session, false);

    fprintf(stdout,"%s\n", json_str);
    write_to_file(json_str);
    free(json_str);

    return 0;
}

static int handle_comm_exec_event(void *ctx, void *data, size_t data_sz)
{
    struct session_context_t *session = data;
    char *json_str;
    if (check_suspect_bins(session->last_comm.command)){
        json_str = session_context_to_json(session,true);
    } else{
        json_str = session_context_to_json(session,false);
    }

    fprintf(stdout,"%s\n", json_str);
    write_to_file(json_str);
    free(json_str);

    return 0;
}


int main(int argc, char **argv)
{
    struct ring_buffer *session_rb = NULL;
    struct ring_buffer *command_rb = NULL;
	struct sshtrack_bpf *skel;
    int err, sock_prog_fd,sock;
    int zero = 0 ;
    struct sshd_info_t sshd_info;

    /* Parse command line arguments*/
    // Check the correct number of arguments
    if (argc > 1) {
        // Copy the file name to a properly-sized buffer
        char buffer[NAME_MAX];
        strncpy(buffer, argv[1], sizeof(buffer));
        buffer[sizeof(buffer) - 1] = '\0'; // Ensure string termination
        strncpy(filename, buffer, sizeof(filename));
    }

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	//libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel = sshtrack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load and verify BPF program */
	err = sshtrack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load or verify BPF skeleton\n");
		goto cleanup;
	}

    /* Loading information about ssh daemon to the map that will be used on kernel side */
    sshd_info.pid = get_sshd_pid();
    if (sshd_info.pid == -1) {
        printf("Failed to retrieve the PID of the sshd process\n");
        goto cleanup;
    }
    sshd_info.uid = get_sshd_uid();
    sshd_info.port = SSHD_PORT;

    if (bpf_map__update_elem(skel->maps.sshd_map,&zero,sizeof(zero),&sshd_info,sizeof (struct sshd_info_t),BPF_ANY) < 0 ){
        fprintf(stderr, "Failed to update map with info about sshd\n");
        goto cleanup;
    }

    session_rb = ring_buffer__new(bpf_map__fd(skel->maps.session_rb), handle_session_start_event, NULL, NULL);
    if (!session_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    command_rb = ring_buffer__new(bpf_map__fd(skel->maps.command_rb), handle_comm_exec_event, NULL, NULL);
    if (!command_rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer2\n");
        goto cleanup;
    }

    /* Create raw socket for every interface with "0" (otherwise pass the name of the interface) */
    sock = open_raw_sock("0");
    if (sock < 0) {
        err = -2;
        fprintf(stderr, "Failed to open raw socket\n");
        goto cleanup;
    }


	/* Attach tracepoints */
	err = sshtrack_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    sock_prog_fd = bpf_program__fd(skel->progs.socket_filter);
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &sock_prog_fd, sizeof(sock_prog_fd))) {
        err = -3;
        fprintf(stderr, "Failed to attach to raw socket\n");
        goto cleanup;
    }

    while(!exiting){
        fflush(stdout);
        err = ring_buffer__poll(session_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(command_rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }

    }

    cleanup:
    /* Clean up */
    ring_buffer__free(session_rb);
    ring_buffer__free(command_rb);
    sshtrack_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
