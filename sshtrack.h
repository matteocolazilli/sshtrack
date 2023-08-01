//
// Created by matteo on 08/02/23.
//

#ifndef SSHPROBE_H
#define SSHPROBE_H

#define ETH_P_IP	0x0800
#define ETH_HLEN	14
#define BUF_SIZE 16
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGV_LEN 62

struct sys_enter_setresuid_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    uid_t ruid;
    uid_t euid;
    uid_t suid;
};

struct sshd_info_t {
    __u16 port;
    pid_t pid;
    uid_t uid;
};

struct binary_context_t {
    __u32 session_cookie;
};

struct comm {
    __u64 timestamp;
    char command[MAX_ARGV_LEN];
    char argv[6][MAX_ARGV_LEN];
};

struct session_context_t {
    __u32 session_cookie;
    __u64 login_timestamp;
    uid_t uid;
    pid_t init_pid;
    __u32 source_addr; //IP source address
    __u16 source_port; //TCP source port
    struct comm last_comm;
};


#endif //SSHPROBE_H
