#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cmath>
#include <cassert>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <thread>

#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <LIEF/LIEF.hpp>
#include <sys/stat.h>

#include "SyscallDecoder.hpp"
#include "UIO.hpp"
#include "IO.hpp"

SyscallDecoder::SyscallDecoder(bool verbose) :
    verbose(verbose),
    syscall_table({
        {"read"                   , "ub3i"    , -1} ,
        {"write"                  , "ub3i"    , -1} ,
        {"open"                   , "suu"    , -1} ,
        {"close"                  , "u"      , -1} ,
        {"stat"                   , "sp"     , -1} ,
        {"fstat"                  , "up"     , -1} ,
        {"lstat"                  , "sp"     , -1} ,
        {"poll"                   , "pui"    , -1} ,
        {"lseek"                  , "uiu"    , -1} ,
        {"mmap"                   , "puuuuu" , -1} ,
        {"mprotect"               , "uiu"    , -1} ,
        {"munmap"                 , "ui"     , -1} ,
        {"brk"                    , "u"      , -1} ,
        {"rt_sigaction"           , "ippi"   , -1} ,
        {"rt_sigprocmask"         , "ippi"   , -1} ,
        {"rt_sigreturn"           , "u"      , -1} ,
        {"ioctl"                  , "uuu"    , -1} ,
        {"pread64"                , "upii"   , -1} ,
        {"pwrite64"               , "upii"   , -1} ,
        {"readv"                  , "upu"    , -1} ,
        {"writev"                 , "upu"    , -1} ,
        {"access"                 , "si"     , -1} ,
        {"pipe"                   , "p"      , -1} ,
        {"select"                 , "ipppp"  , -1} ,
        {"sched_yield"            , ""       , -1} ,
        {"mremap"                 , "uuuuu"  , -1} ,
        {"msync"                  , "uii"    , -1} ,
        {"mincore"                , "uip"    , -1} ,
        {"madvise"                , "uii"    , -1} ,
        {"shmget"                 , "uii"    , -1} ,
        {"shmat"                  , "ipi"    , -1} ,
        {"shmctl"                 , "iip"    , -1} ,
        {"dup"                    , "u"      , -1} ,
        {"dup2"                   , "uu"     , -1} ,
        {"pause"                  , ""       , -1} ,
        {"nanosleep"              , "pp"     , -1} ,
        {"getitimer"              , "ip"     , -1} ,
        {"alarm"                  , "u"      , -1} ,
        {"setitimer"              , "ipp"    , -1} ,
        {"getpid"                 , ""       , -1} ,
        {"sendfile"               , "iipi"   , -1} ,
        {"socket"                 , "iii"    , -1} ,
        {"connect"                , "ipi"    , -1} ,
        {"accept"                 , "ipp"    , -1} ,
        {"sendto"                 , "ipiupi" , -1} ,
        {"recvfrom"               , "ipiupi" , -1} ,
        {"sendmsg"                , "ipu"    , -1} ,
        {"recvmsg"                , "ipu"    , -1} ,
        {"shutdown"               , "ii"     , -1} ,
        {"bind"                   , "ipi"    , -1} ,
        {"listen"                 , "ii"     , -1} ,
        {"getsockname"            , "ipp"    , -1} ,
        {"getpeername"            , "ipp"    , -1} ,
        {"socketpair"             , "iiip"   , -1} ,
        {"setsockopt"             , "iiipi"  , -1} ,
        {"getsockopt"             , "iiipp"  , -1} ,
        {"clone"                  , "uupp"   , -1} ,
        {"fork"                   , ""       , -1} ,
        {"vfork"                  , ""       , -1} ,
        {"execve"                 , "ppp"    , -1} ,
        {"exit"                   , "i"      , -1} ,
        {"wait4"                  , "upip"   , -1} ,
        {"kill"                   , "ui"     , -1} ,
        {"uname"                  , "p"      , -1} ,
        {"semget"                 , "uii"    , -1} ,
        {"semop"                  , "ipu"    , -1} ,
        {"semctl"                 , "iiig"   , -1} ,
        {"shmdt"                  , "p"      , -1} ,
        {"msgget"                 , "ui"     , -1} ,
        {"msgsnd"                 , "ipii"   , -1} ,
        {"msgrcv"                 , "ipiii"  , -1} ,
        {"msgctl"                 , "iip"    , -1} ,
        {"fcntl"                  , "uuu"    , -1} ,
        {"flock"                  , "uu"     , -1} ,
        {"fsync"                  , "u"      , -1} ,
        {"fdatasync"              , "u"      , -1} ,
        {"truncate"               , "si"     , -1} ,
        {"ftruncate"              , "uu"     , -1} ,
        {"getdents"               , "upu"    , -1} ,
        {"getcwd"                 , "pu"     , -1} ,
        {"chdir"                  , "s"      , -1} ,
        {"fchdir"                 , "u"      , -1} ,
        {"rename"                 , "ss"     , -1} ,
        {"mkdir"                  , "si"     , -1} ,
        {"rmdir"                  , "s"      , -1} ,
        {"creat"                  , "si"     , -1} ,
        {"link"                   , "ss"     , -1} ,
        {"unlink"                 , "s"      , -1} ,
        {"symlink"                , "ss"     , -1} ,
        {"readlink"               , "spi"    , -1} ,
        {"chmod"                  , "sg"     , -1} ,
        {"fchmod"                 , "ug"     , -1} ,
        {"chown"                  , "suu"    , -1} ,
        {"fchown"                 , "uuu"    , -1} ,
        {"lchown"                 , "suu"    , -1} ,
        {"umask"                  , "i"      , -1} ,
        {"gettimeofday"           , "pp"     , -1} ,
        {"getrlimit"              , "up"     , -1} ,
        {"getrusage"              , "ip"     , -1} ,
        {"sysinfo"                , "p"      , -1} ,
        {"times"                  , "p"      , -1} ,
        {"ptrace"                 , "iiuu"   , -1} ,
        {"getuid"                 , ""       , -1} ,
        {"syslog"                 , "ipi"    , -1} ,
        {"getgid"                 , ""       , -1} ,
        {"setuid"                 , "u"      , -1} ,
        {"setgid"                 , "u"      , -1} ,
        {"geteuid"                , ""       , -1} ,
        {"getegid"                , ""       , -1} ,
        {"setpgid"                , "uu"     , -1} ,
        {"getppid"                , ""       , -1} ,
        {"getpgrp"                , ""       , -1} ,
        {"setsid"                 , ""       , -1} ,
        {"setreuid"               , "uu"     , -1} ,
        {"setregid"               , "uu"     , -1} ,
        {"getgroups"              , "ip"     , -1} ,
        {"setgroups"              , "ip"     , -1} ,
        {"setresuid"              , "ppp"    , -1} ,
        {"getresuid"              , "ppp"    , -1} ,
        {"setresgid"              , "uuu"    , -1} ,
        {"getresgid"              , "ppp"    , -1} ,
        {"getpgid"                , "u"      , -1} ,
        {"setfsuid"               , "u"      , -1} ,
        {"setfsgid"               , "u"      , -1} ,
        {"getsid"                 , "u"      , -1} ,
        {"capget"                 , "gg"     , -1} ,
        {"capset"                 , "gg"     , -1} ,
        {"rt_sigpending"          , "pi"     , -1} ,
        {"rt_sigtimedwait"        , "pppi"   , -1} ,
        {"rt_sigqueueinfo"        , "uip"    , -1} ,
        {"rt_sigsuspend"          , "pi"     , -1} ,
        {"sigaltstack"            , "pp"     , -1} ,
        {"utime"                  , "sp"     , -1} ,
        {"mknod"                  , "sgu"    , -1} ,
        {"uselib"                 , ""       , -1} ,
        {"personality"            , "u"      , -1} ,
        {"ustat"                  , "up"     , -1} ,
        {"statfs"                 , "pp"     , -1} ,
        {"fstatfs"                , "up"     , -1} ,
        {"sysfs"                  , "iuu"    , -1} ,
        {"getpriority"            , "ii"     , -1} ,
        {"setpriority"            , "iii"    , -1} ,
        {"sched_setparam"         , "up"     , -1} ,
        {"sched_getparam"         , "up"     , -1} ,
        {"sched_setscheduler"     , "uip"    , -1} ,
        {"sched_getscheduler"     , "u"      , -1} ,
        {"sched_get_priority_max" , "i"      , -1} ,
        {"sched_get_priority_min" , "i"      , -1} ,
        {"sched_rr_get_interval"  , "up"     , -1} ,
        {"mlock"                  , "ui"     , -1} ,
        {"munlock"                , "ui"     , -1} ,
        {"mlockall"               , "i"      , -1} ,
        {"munlockall"             , ""       , -1} ,
        {"vhangup"                , ""       , -1} ,
        {"modify_ldt"             , "ipu"    , -1} ,
        {"pivot_root"             , "pp"     , -1} ,
        {"_sysctl"                , "p"      , -1} ,
        {"prctl"                  , "iggggg" , -1} ,
        {"arch_prctl"             , "pip"    , -1} ,
        {"adjtimex"               , "p"      , -1} ,
        {"setrlimit"              , "up"     , -1} ,
        {"chroot"                 , "p"      , -1} ,
        {"sync"                   , ""       , -1} ,
        {"acct"                   , "p"      , -1} ,
        {"settimeofday"           , "pp"     , -1} ,
        {"mount"                  , "sssup"  , -1} ,
        {"umount2"                , "si"     , -1} ,
        {"swapon"                 , "si"     , -1} ,
        {"swapoff"                , "s"      , -1} ,
        {"reboot"                 , "ggup"   , -1} ,
        {"sethostname"            , "pi"     , -1} ,
        {"setdomainname"          , "pi"     , -1} ,
        {"iopl"                   , "up"     , -1} ,
        {"ioperm"                 , "uui"    , -1} ,
        {"create_module"          , ""       , -1} ,
        {"init_module"            , "pup"    , -1} ,
        {"delete_module"          , "pu"     , -1} ,
        {"get_kernel_syms"        , ""       , -1} ,
        {"query_module"           , ""       , -1} ,
        {"quotactl"               , "upgp"   , -1} ,
        {"nfsservctl"             , ""       , -1} ,
        {"getpmsg"                , ""       , -1} ,
        {"putpmsg"                , ""       , -1} ,
        {"afs_syscall"            , ""       , -1} ,
        {"tuxcall"                , ""       , -1} ,
        {"security"               , ""       , -1} ,
        {"gettid"                 , ""       , -1} ,
        {"readahead"              , "iii"    , -1} ,
        {"setxattr"               , "sspii"  , -1} ,
        {"lsetxattr"              , "sspii"  , -1} ,
        {"fsetxattr"              , "sspii"  , -1} ,
        {"getxattr"               , "sspi"   , -1} ,
        {"lgetxattr"              , "sspi"   , -1} ,
        {"fgetxattr"              , "sspi"   , -1} ,
        {"listxattr"              , "spi"    , -1} ,
        {"llistxattr"             , "spi"    , -1} ,
        {"flistxattr"             , "ipi"    , -1} ,
        {"removexattr"            , "ss"     , -1} ,
        {"lremovexattr"           , "ss"     , -1} ,
        {"fremovexattr"           , "is"     , -1} ,
        {"tkill"                  , "ui"     , -1} ,
        {"time"                   , "p"      , -1} ,
        {"futex"                  , "piuppu" , -1} ,
        {"sched_setaffinity"      , "uup"    , -1} ,
        {"sched_getaffinity"      , "uup"    , -1} ,
        {"set_thread_area"        , ""       , -1} ,
        {"io_setup"               , "up"     , -1} ,
        {"io_destroy"             , "g"      , -1} ,
        {"io_getevents"           , "giip"   , -1} ,
        {"io_submit"              , "gip"    , -1} ,
        {"io_cancel"              , "gpp"    , -1} ,
        {"get_thread_area"        , ""       , -1} ,
        {"lookup_dcookie"         , "uii"    , -1} ,
        {"epoll_create"           , ""       , -1} ,
        {"epoll_ctl_old"          , ""       , -1} ,
        {"epoll_wait_old"         , ""       , -1} ,
        {"remap_file_pages"       , "uuuuu"  , -1} ,
        {"getdents64"             , "upu"    , -1} ,
        {"set_tid_address"        , "p"      , -1} ,
        {"restart_syscall"        , ""       , -1} ,
        {"semtimedop"             , "ipup"   , -1} ,
        {"fadvise64"              , "iiii"   , -1} ,
        {"timer_create"           , "gpp"    , -1} ,
        {"timer_settime"          , "uipp"   , -1} ,
        {"timer_gettime"          , "up"     , -1} ,
        {"timer_getoverrun"       , "u"      , -1} ,
        {"timer_delete"           , "u"      , -1} ,
        {"clock_settime"          , "gp"     , -1} ,
        {"clock_gettime"          , "gp"     , -1} ,
        {"clock_getres"           , "gp"     , -1} ,
        {"clock_nanosleep"        , "gipp"   , -1} ,
        {"exit_group"             , "i"      , -1} ,
        {"epoll_wait"             , "ipii"   , -1} ,
        {"epoll_ctl"              , "iiip"   , -1} ,
        {"tgkill"                 , "uui"    , -1} ,
        {"utimes"                 , "sp"     , -1} ,
        {"vserver"                , ""       , -1} ,
        {"mbind"                  , "uuupuu" , -1} ,
        {"set_mempolicy"          , "ipu"    , -1} ,
        {"get_mempolicy"          , "ppuuu"  , -1} ,
        {"mq_open"                , "siup"   , -1} ,
        {"mq_unlink"              , "s"      , -1} ,
        {"mq_timedsend"           , "gpiup"  , -1} ,
        {"mq_timedreceive"        , "gpipp"  , -1} ,
        {"mq_notify"              , "gp"     , -1} ,
        {"mq_getsetattr"          , "gpp"    , -1} ,
        {"kexec_load"             , "uupu"   , -1} ,
        {"waitid"                 , "iupip"  , -1} ,
        {"add_key"                , "sspi"   , -1} ,
        {"request_key"            , "sssg"   , -1} ,
        {"keyctl"                 , "iuuuu"  , -1} ,
        {"ioprio_set"             , "iii"    , -1} ,
        {"ioprio_get"             , "ii"     , -1} ,
        {"inotify_init"           , ""       , -1} ,
        {"inotify_add_watch"      , "isu"    , -1} ,
        {"inotify_rm_watch"       , "ii"     , -1} ,
        {"migrate_pages"          , "uupp"   , -1} ,
        {"openat"                 , "usii"   , -1} ,
        {"mkdirat"                , "usi"    , -1} ,
        {"mknodat"                , "isiu"   , -1} ,
        {"fchownat"               , "isuui"  , -1} ,
        {"futimesat"              , "isp"    , -1} ,
        {"newfstatat"             , "ispi"   , -1} ,
        {"unlinkat"               , "isi"    , -1} ,
        {"renameat"               , "isis"   , -1} ,
        {"linkat"                 , "isisi"  , -1} ,
        {"symlinkat"              , "sis"    , -1} ,
        {"readlinkat"             , "ispi"   , -1} ,
        {"fchmodat"               , "isg"    , -1} ,
        {"faccessat"              , "isi"    , -1} ,
        {"pselect6"               , "ippppp" , -1} ,
        {"ppoll"                  , "pippi"  , -1} ,
        {"unshare"                , "u"      , -1} ,
        {"set_robust_list"        , "pi"     , -1} ,
        {"get_robust_list"        , "ipp"    , -1} ,
        {"splice"                 , "ipipiu" , -1} ,
        {"tee"                    , "iiiu"   , -1} ,
        {"sync_file_range"        , "iiii"   , -1} ,
        {"vmsplice"               , "ipuu"   , -1} ,
        {"move_pages"             , "uupppi" , -1} ,
        {"utimensat"              , "ispi"   , -1} ,
        {"epoll_pwait"            , "ipiipi" , -1} ,
        {"signalfd"               , "ipi"    , -1} ,
        {"timerfd_create"         , "ii"     , -1} ,
        {"eventfd"                , "u"      , -1} ,
        {"fallocate"              , "iiii"   , -1} ,
        {"timerfd_settime"        , "iipp"   , -1} ,
        {"timerfd_gettime"        , "ip"     , -1} ,
        {"accept4"                , "ippi"   , -1} ,
        {"signalfd4"              , "ipii"   , -1} ,
        {"eventfd2"               , "ui"     , -1} ,
        {"epoll_create1"          , "i"      , -1} ,
        {"dup3"                   , "uui"    , -1} ,
        {"pipe2"                  , "pi"     , -1} ,
        {"inotify_init1"          , "i"      , -1} ,
        {"preadv"                 , "upuuu"  , -1} ,
        {"pwritev"                , "upuuu"  , -1} ,
        {"rt_tgsigqueueinfo"      , "uuip"   , -1} ,
        {"perf_event_open"        , "puiiu"  , -1} ,
        {"recvmmsg"               , "ipuup"  , -1} ,
        {"fanotify_init"          , "uu"     , -1} ,
        {"fanotify_mark"          , "iiuii"  , -1} ,
        {"prlimit64"              , "uupp"   , -1} ,
        {"name_to_handle_at"      , "isppi"  , -1} ,
        {"open_by_handle_at"      , "isppi"  , -1} ,
        {"clock_adjtime"          , "gp"     , -1} ,
        {"syncfs"                 , "i"      , -1} ,
        {"sendmmsg"               , "ipuu"   , -1} ,
        {"setns"                  , "ii"     , -1} ,
        {"getcpu"                 , "ppp"    , -1} ,
        {"process_vm_readv"       , "upupuu" , -1} ,
        {"process_vm_writev"      , "upupuu" , -1} ,
        {"kcmp"                   , "uuiuu"  , -1} ,
        {"finit_module"           , "ipi"    , -1} ,
        {"sched_setattr"          , "upu"    , -1} ,
        {"sched_getattr"          , "upuu"   , -1} ,
        {"renameat2"              , "isisi"  , -1} ,
        {"seccomp"                , "uup"    , -1} ,
        {"getrandom"              , "piu"    , -1} ,
        {"memfd_create"           , "su"     , -1} ,
        {"kexec_file_load"        , "iiupu"  , -1} ,
        {"bpf"                    , "ipu"    , -1} ,
        {"execveat"               , "isssi"  , -1} ,
        {"userfaultfd"            , "i"      , -1} ,
        {"membarrier"             , "ii"     , -1} ,
        {"mlock2"                 , "uii"    , -1} ,
        {"copy_file_range"        , "ipipiu" , -1} ,
        {"preadv2"                , "upuuui" , -1} ,
        {"pwritev2"               , "upuuui" , -1} ,
        })
{
    return;
}

SyscallDecoder::~SyscallDecoder() {
    return;
}

void SyscallDecoder::decode(uint64_t nbr, uint64_t *params, uint64_t ret) {
    int size;
    std::cout << getpid() << ":  " << this->syscall_table[nbr].name << "(";
    char *ptr = this->syscall_table[nbr].param_format;

    int idx = 0;
    while(*ptr) {
        switch(*ptr){
            case 'i':
                printf("%lli", (long long int)params[idx]);
                break;
            case 'u':
                printf("%llu", (long long unsigned int)params[idx]);
                break;
            case 'g':
            case 'x':
            case 'p':
                printf("0x%llx", (long long unsigned int)params[idx]);
                break;
            case 's':
                printf("'%s'", (char*)params[idx]);
                break;
            case 'b':
                ptr++;
                putchar('\'');
                for(size = 0; size < params[*ptr - 48 - 1] && size < 64; size++){
                    switch(*((char*)params[idx] + size)){
                        case '\n':
                            putchar('\\');
                            putchar('n');
                            break;
                        case '\r':
                            putchar('\\');
                            putchar('r');
                            break;
                        default:
                            putchar(*((char*)params[idx] + size));
                    }
                }
                putchar('\'');
                break;
            default:
                std::cout << "ERROR UNKNOWN FORMAT";
        }

        std::cout << ", ";
        idx++;
        ptr++;
    }

    std::cout << ") = 0x" << std::hex << ret;

    if(ret == this->syscall_table[nbr].error_code) {
        std::cout << " (" << strerror(errno) << ")";
    }

    std::cout << std::endl;
    return;
}
