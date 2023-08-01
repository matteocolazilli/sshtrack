#include "vmlinux.h"
#include "sshtrack.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, u32);
    __type(value, struct session_context_t);
    __uint(max_entries, 5000);
} session_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct binary_context_t);
    __uint(max_entries, 32000);
} pid_binary_context SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct sshd_info_t);
} sshd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_t);
    __type(value, struct session_context_t);
    __uint(max_entries, 256);
} pid_session SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} session_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} command_rb SEC(".maps");


SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
    __u16 h_proto;
    __u8 ip_proto;
    __u8 verlen;
    __be16 tcp_dest_port;
    __be16 tcp_source_port;
    __be32 daddr;

    struct sshd_info_t *sshd_info;
    int const zero = 0;
    int err;

    sshd_info = bpf_map_lookup_elem(&sshd_map,&zero);

    if (sshd_info == NULL){
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    pid_t ppid;

    err = BPF_CORE_READ_INTO(&ppid,task,real_parent,pid);
    if (err){
        return 0;
    }

    if (ppid != sshd_info->pid){
        // If ppid is not that of sshd we know that the packet is not the one
        // received by the sshd child process that handles the current login
        return 0;
    }

    pid_t pid;

    err = BPF_CORE_READ_INTO(&pid,task,pid);
    if (err){
        return 0;
    }

    // Retrieve session associated with the pid
    struct session_context_t *session = bpf_map_lookup_elem(&pid_session,&pid);

    if (session != NULL){
        //pid is already associated with a session so
        // it doesn't need to be associated again
        return 0;
    }

    struct session_context_t new_session = {};

    //Retrieve protocol from Ethernet header
    bpf_skb_load_bytes(skb, 12, &h_proto, 2);
    h_proto = bpf_ntohs(h_proto);

    //Verify that the protocol is IP
    if (h_proto != ETH_P_IP) {
        return 0;
    }

    //Retrieve protocol from IP header
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &ip_proto, 1);

    //Verify that protocol is TCP
    if (ip_proto != IPPROTO_TCP) {
        return 0;
    }

    //Retrieve Version and Header Length byte
    bpf_skb_load_bytes(skb, ETH_HLEN + 0, &verlen, 1);

    // Retrieve TCP source port
    bpf_skb_load_bytes(skb, ETH_HLEN + ((verlen & 0xF) << 2), &tcp_source_port, 2);
    tcp_source_port = bpf_ntohs(tcp_source_port);

    //Check if TCP source port is sshd_port
    if (tcp_source_port != sshd_info->port){
        return 0;
    }

    //Retrieve TCP destination port
    bpf_skb_load_bytes(skb, ETH_HLEN + ((verlen & 0xF) << 2) + 2, &tcp_dest_port, 2);
    tcp_dest_port = bpf_ntohs(tcp_dest_port);

    // Retrieve IP source address
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, 4);

    new_session.source_addr = (__u32)daddr;
    new_session.source_port = (__u16)tcp_dest_port;

    if(bpf_map_update_elem(&pid_session,&pid,&new_session,BPF_ANY)<0){
        return 0;
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    uid_t ruid = BPF_CORE_READ(ctx,args[0]);
    uid_t euid = BPF_CORE_READ(ctx,args[1]);
    uid_t suid = BPF_CORE_READ(ctx,args[2]);

    int const zero = 0;
    struct sshd_info_t *sshd_info;
    int err;

    // Retrieving infos about running SSH daemon
    sshd_info = bpf_map_lookup_elem(&sshd_map,&zero);
    if (sshd_info == NULL) {
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();
    pid_t ppid;

    err = BPF_CORE_READ_INTO(&ppid,task,real_parent,pid);
    if (err){
        return 0;
    }

    struct session_context_t *session = bpf_map_lookup_elem(&pid_session,&ppid);
    // if ppid is already associated to a session then the process in which setresuid is called
    // maybe is the right one
    if (session == NULL) {
        return 0;
    }

    // Checking if parameters of setresuid call match the right pattern which
    // indicates us that the call to trace is the right one
    if ((ruid == euid) && (euid == suid) && (euid != sshd_info->uid)) {

        pid_t pid;

        err = BPF_CORE_READ_INTO(&pid,task,pid);
        if (err){
            return 0;
        }

        __u32 session_cookie = bpf_get_prandom_u32();
        session->init_pid = pid;
        session->session_cookie = session_cookie;
        session->uid = euid;
        session->login_timestamp = bpf_ktime_get_boot_ns();

        bpf_ringbuf_output(&session_rb, session, sizeof(*session), 0);

        // Update the session cookie <-> session context mapping
        bpf_map_update_elem(&session_context, &session_cookie, session, BPF_ANY);

        // Update the pid <-> session mapping
        struct binary_context_t new_binary_ctx = {};
        new_binary_ctx.session_cookie = session_cookie;
        bpf_map_update_elem(&pid_binary_context, &pid, &new_binary_ctx, BPF_ANY);

        return 0;
    }
    return 0;
}

/*
 * Used to track child processes and inherit session cookies
 */
SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint_clone(struct trace_event_raw_sys_exit *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // get binary context
    struct binary_context_t *parent_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (parent_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // inherit session cookie
    u32 child_pid = (u32) ctx->ret;
    if (child_pid <= 0){
        return 0;
    }
    struct binary_context_t child_ctx = {};
    child_ctx.session_cookie = parent_ctx->session_cookie;
    bpf_map_update_elem(&pid_binary_context, &child_pid, &child_ctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    char *argv_ptr;
    char *argv[7];
    u32 cookie;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // get binary context
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // select profile cookie
    cookie = binary_ctx->session_cookie;
    struct session_context_t *session = bpf_map_lookup_elem(&session_context, &cookie);
    if (session == NULL) {
        return 0;
    }

    session->last_comm.timestamp = bpf_ktime_get_boot_ns();

    // retrieve pointer to args pointers array
    argv_ptr = (char *) BPF_CORE_READ(ctx, args[1]);

    // read args pointers array
    bpf_core_read_user(&argv, sizeof(argv), argv_ptr);

    // read args into the session struct
    bpf_probe_read_user_str(session->last_comm.command,sizeof session->last_comm.command,argv[0]);
    bpf_probe_read_user_str(session->last_comm.argv[0],sizeof session->last_comm.argv[0],argv[1]);
    bpf_probe_read_user_str(session->last_comm.argv[1],sizeof session->last_comm.argv[1],argv[2]);
    bpf_probe_read_user_str(session->last_comm.argv[2],sizeof session->last_comm.argv[2],argv[3]);
    bpf_probe_read_user_str(session->last_comm.argv[3],sizeof session->last_comm.argv[3],argv[4]);
    bpf_probe_read_user_str(session->last_comm.argv[4],sizeof session->last_comm.argv[4],argv[5]);
    bpf_probe_read_user_str(session->last_comm.argv[5],sizeof session->last_comm.argv[5],argv[6]);

    if (bpf_ringbuf_output(&command_rb,session,sizeof (*session),0) < 0){
        return 0;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
