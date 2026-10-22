/*
 * apu_shield.so: self-destruct shield for Ijiami (and similar) x86_64
 * shells on redroid / emulator profiles.
 *
 * Injected with LD_PRELOAD through Android's wrap.<package> property before
 * the app's native shell starts.  A tiny helper process (forked before the
 * seccomp filter is installed, so it is itself unfiltered) receives seccomp
 * user-notification events and:
 *   - serves sanitized /proc/self/maps, /proc/<pid>/maps, /proc/self/status,
 *     /proc/self/wchan, /proc/tty/drivers and /proc/self/environ
 *   - suppresses self-directed SIGKILL and exit_group
 * This keeps the shell alive long enough to load/decrypt the payload without
 * exposing a ptrace tracer (TracerPid stays 0) or Frida (no agent maps).
 *
 * No libc dependency: only x86_64 raw syscalls are used, so the library can
 * be compiled with plain `gcc -shared -fPIC -nostdlib` and loaded into bionic.
 */
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;

#define SYS_write 1
#define SYS_close 3
#define SYS_lseek 8
#define SYS_rt_sigaction 13
#define SYS_ioctl 16
#define SYS_pause 34
#define SYS_rt_sigreturn 15
#define SYS_socketpair 53
#define SYS_fork 57
#define SYS_exit_group 231
#define SYS_openat 257
#define SYS_process_vm_readv 310
#define SYS_process_vm_writev 311
#define SYS_seccomp 317
#define SYS_memfd_create 319
#define SYS_prctl 157
#define SYS_recvmsg 47
#define SYS_sendmsg 46
#define SYS_getppid 110
#define SYS_getpid 39

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define O_APPEND 1024
#define O_TRUNC 512
#define SEEK_SET 0

#define SIGILL 4
#define SIGSEGV 11
#define SIGABRT 6
#define SIGBUS 7
#define SA_SIGINFO 4
#define SA_RESTORER 0x04000000

#define PR_SET_NAME 15
#define PR_SET_DUMPABLE 4
#define PR_SET_PTRACER 0x59616d61
#define PR_SET_NO_NEW_PRIVS 38

#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_FILTER_FLAG_TSYNC 1
#define SECCOMP_FILTER_FLAG_NEW_LISTENER 8
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define SECCOMP_RET_USER_NOTIF 0x7fc00000u

#define AUDIT_ARCH_X86_64 0xC000003Eu

#define SECCOMP_IOCTL_NOTIF_RECV 0xC0502100UL
#define SECCOMP_IOCTL_NOTIF_SEND 0xC0182101UL
#define SECCOMP_IOCTL_NOTIF_ADDFD 0x40182103UL

#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1u
#define SECCOMP_ADDFD_FLAG_SEND 2u

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SCM_RIGHTS 1

#define MAP_SIZE (2 * 1024 * 1024)

struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; };
struct sock_fprog { u16 len; struct sock_filter *filter; };
struct iovec { void *iov_base; unsigned long iov_len; };
struct msghdr {
  void *msg_name;
  unsigned int msg_namelen;
  struct iovec *msg_iov;
  unsigned long msg_iovlen;
  void *msg_control;
  unsigned long msg_controllen;
  int msg_flags;
};
struct cmsghdr {
  unsigned long cmsg_len;
  int cmsg_level;
  int cmsg_type;
};
struct seccomp_data {
  int nr;
  u32 arch;
  u64 instruction_pointer;
  u64 args[6];
};
struct seccomp_notif {
  u64 id;
  u32 pid;
  u32 flags;
  struct seccomp_data data;
};
struct seccomp_notif_resp {
  u64 id;
  s64 val;
  s32 error;
  u32 flags;
};
struct seccomp_notif_addfd {
  u64 id;
  u32 flags;
  u32 srcfd;
  u32 newfd;
  u32 newfd_flags;
};

static char path_buf[4096];
static char content_buf[MAP_SIZE];

static long sys6(long n, long a, long b, long c, long d, long e, long f) {
  register long r10 __asm__("r10") = d;
  register long r8 __asm__("r8") = e;
  register long r9 __asm__("r9") = f;
  long ret;
  __asm__ volatile("syscall" : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

#define CMSG_ALIGN(l) (((l) + sizeof(unsigned long) - 1) & ~(sizeof(unsigned long) - 1))
#define CMSG_SPACE(l) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(l))
#define CMSG_LEN(l) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (l))
#define CMSG_DATA(c) ((unsigned char *)(c) + CMSG_ALIGN(sizeof(struct cmsghdr)))

static unsigned long slen(const char *s) {
  unsigned long n = 0;
  while (s[n]) n++;
  return n;
}

static int seq(const char *a, const char *b) {
  while (*a && *b) {
    if (*a != *b) return (int)(unsigned char)*a - (int)(unsigned char)*b;
    a++; b++;
  }
  return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static int starts(const char *s, const char *p) {
  while (*p) {
    if (*s != *p) return 0;
    s++; p++;
  }
  return 1;
}

static int find_sub(const char *hay, const char *needle) {
  if (!*needle) return 1;
  for (; *hay; hay++) {
    if (starts(hay, needle)) return 1;
  }
  return 0;
}

static long append_str(char *dst, long n, long max, const char *s, long len) {
  if (len < 0) len = (long)slen(s);
  for (long i = 0; i < len && n < max - 1; i++) dst[n++] = s[i];
  dst[n] = 0;
  return n;
}

static long append_dec(char *dst, long n, long max, long value) {
  char tmp[24];
  int d = 0;
  unsigned long v;
  if (value < 0) { if (n < max - 1) dst[n++] = '-'; v = (unsigned long)(-value); }
  else v = (unsigned long)value;
  if (v == 0) tmp[d++] = '0';
  while (v && d < 20) { tmp[d++] = (char)('0' + (v % 10)); v /= 10; }
  while (d > 0 && n < max - 1) dst[n++] = tmp[--d];
  dst[n] = 0;
  return n;
}

static long write_all(long fd, const char *buf, long len) {
  long done = 0;
  while (done < len) {
    long n = sys6(SYS_write, fd, (long)(buf + done), len - done, 0, 0, 0);
    if (n <= 0) break;
    done += n;
  }
  return done;
}

static void log_value(const char *prefix, long value) {
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/data/local/tmp/apu_shield.log",
                 O_WRONLY | O_CREAT | O_APPEND, 0666, 0, 0);
  if (fd < 0) return;
  char buf[160];
  long n = append_str(buf, 0, sizeof(buf), prefix, -1);
  n = append_str(buf, n, sizeof(buf), "=", 1);
  n = append_dec(buf, n, sizeof(buf), value);
  n = append_str(buf, n, sizeof(buf), "\n", 1);
  write_all(fd, buf, n);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static void log_hex(const char *prefix, const unsigned char *data, long len) {
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/data/local/tmp/apu_shield.log",
                 O_WRONLY | O_CREAT | O_APPEND, 0666, 0, 0);
  if (fd < 0) return;
  char buf[256];
  long n = append_str(buf, 0, sizeof(buf), prefix, -1);
  n = append_str(buf, n, sizeof(buf), "=", 1);
  const char *hex = "0123456789abcdef";
  for (long i = 0; i < len && n < 240; i++) {
    buf[n++] = hex[(data[i] >> 4) & 0xf];
    buf[n++] = hex[data[i] & 0xf];
  }
  buf[n++] = '\n';
  write_all(fd, buf, n);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static void log_path(const char *prefix, const char *path) {
  long fd = sys6(SYS_openat, AT_FDCWD, (long)"/data/local/tmp/apu_shield.log",
                 O_WRONLY | O_CREAT | O_APPEND, 0666, 0, 0);
  if (fd < 0) return;
  char buf[512];
  long n = append_str(buf, 0, sizeof(buf), prefix, -1);
  n = append_str(buf, n, sizeof(buf), "=", 1);
  long plen = (long)slen(path);
  if (plen > 380) plen = 380;
  n = append_str(buf, n, sizeof(buf), path, plen);
  n = append_str(buf, n, sizeof(buf), "\n", 1);
  write_all(fd, buf, n);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static long read_file(const char *path, char *buf, long max) {
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
  if (fd < 0) return -1;
  long total = 0;
  while (total < max - 1) {
    long n = sys6(0 /* read */, fd, (long)(buf + total), max - 1 - total, 0, 0, 0);
    if (n <= 0) break;
    total += n;
  }
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  buf[total] = 0;
  return total;
}

static const char *BAD_MAP_TOKENS[] = {
  "libapu",
};
#define BAD_MAP_TOKEN_COUNT (sizeof(BAD_MAP_TOKENS) / sizeof(BAD_MAP_TOKENS[0]))

static int bad_map_line(const char *line, long len) {
  for (unsigned long i = 0; i < BAD_MAP_TOKEN_COUNT; i++) {
    const char *tok = BAD_MAP_TOKENS[i];
    long tl = (long)slen(tok);
    if (tl > len) continue;
    for (long off = 0; off + tl <= len; off++) {
      int ok = 1;
      for (long j = 0; j < tl; j++) {
        if (line[off + j] != tok[j]) { ok = 0; break; }
      }
      if (ok) return 1;
    }
  }
  return 0;
}

static const char CPUINFO_FAKE[] =
  "processor\t: 0\n"
  "BogoMIPS\t: 38.40\n"
  "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n"
  "CPU implementer\t: 0x41\n"
  "CPU architecture: 8\n"
  "CPU variant\t: 0x0\n"
  "CPU part\t: 0xd03\n"
  "CPU revision\t: 4\n"
  "\n"
  "Hardware\t: Qualcomm Technologies, Inc MSM8953\n"
  "Revision\t: 0000\n"
  "Serial\t\t: 0000000000000000\n";

static const char BUILD_PROP_FAKE[] =
  "ro.product.cpu.abi=arm64-v8a\n"
  "ro.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi\n"
  "ro.product.cpu.abilist64=arm64-v8a\n"
  "ro.product.cpu.abilist32=armeabi-v7a,armeabi\n"
  "ro.dalvik.vm.native.bridge=\n"
  "ro.debuggable=0\n"
  "ro.secure=1\n"
  "ro.build.tags=release-keys\n"
  "ro.build.type=user\n"
  "ro.product.model=Redmi Note 8\n"
  "ro.product.manufacturer=Xiaomi\n"
  "ro.product.brand=Xiaomi\n"
  "ro.product.device=whyred\n"
  "ro.product.name=whyred\n"
  "ro.board.platform=msm8953\n"
  "ro.hardware=qcom\n"
  "ro.build.fingerprint=Xiaomi/redmi_note8/whyred:11/RKQ1.201217.002/V12.5.1.0.PEIMIXM:user/release-keys\n";

static const char TTY_FAKE[] =
  "/dev/tty             /dev/tty             major   5 minor   0 system:/dev/tty\n"
  "/dev/console         /dev/console         major   5 minor   1 system:console\n"
  "/dev/ptmx            /dev/ptmx            major   5 minor   2 system:ptmx\n"
  "/dev/vc/0            /dev/vc/0            major   4 minor   0 system:vc/0\n"
  "/dev/tty0            /dev/tty0            major   4 minor   0 system:tty0\n";

static void make_proc_path(char *out, long size, long pid, const char *suffix) {
  long n = append_str(out, 0, size, "/proc/", -1);
  n = append_dec(out, n, size, pid);
  append_str(out, n, size, suffix, -1);
}

static long tgid_of(long pid) {
  char path[80];
  char buf[4096];
  make_proc_path(path, sizeof(path), pid, "/status");
  long n = read_file(path, buf, sizeof(buf));
  if (n <= 0) return pid;
  for (long i = 0; i + 5 < n; i++) {
    if (buf[i] == 'T' && buf[i+1] == 'g' && buf[i+2] == 'i' && buf[i+3] == 'd' && buf[i+4] == ':') {
      long j = i + 5;
      while (j < n && (buf[j] == ' ' || buf[j] == '\t')) j++;
      long v = 0;
      while (j < n && buf[j] >= '0' && buf[j] <= '9') { v = v * 10 + (buf[j] - '0'); j++; }
      if (v > 0) return v;
      break;
    }
  }
  return pid;
}

static long build_fake_maps(long pid, char *out, long max) {
  char real[MAP_SIZE];
  char path[80];
  make_proc_path(path, sizeof(path), pid, "/maps");
  long n = read_file(path, real, sizeof(real));
  if (n <= 0) return -1;
  long o = 0;
  long line_start = 0;
  for (long i = 0; i <= n; i++) {
    if (i == n || real[i] == '\n') {
      long line_len = i - line_start;
      if (line_len > 0 && !bad_map_line(real + line_start, line_len)) {
        o = append_str(out, o, max, real + line_start, line_len);
        o = append_str(out, o, max, "\n", 1);
      }
      line_start = i + 1;
    }
  }
  return o;
}

static long build_fake_status(long pid, char *out, long max) {
  char real[8192];
  char path[80];
  make_proc_path(path, sizeof(path), pid, "/status");
  long n = read_file(path, real, sizeof(real));
  if (n <= 0) return -1;
  long o = 0;
  long ls = 0;
  for (long i = 0; i <= n; i++) {
    if (i == n || real[i] == '\n') {
      long ll = i - ls;
      const char *line = real + ls;
      int handled = 0;
      if (ll >= 9 && starts(line, "TracerPid:")) {
        o = append_str(out, o, max, "TracerPid:\t0\n", -1); handled = 1;
      } else if (ll >= 8 && starts(line, "Seccomp:")) {
        o = append_str(out, o, max, "Seccomp:\t0\n", -1); handled = 1;
      } else if (ll >= 16 && starts(line, "Seccomp_filters:")) {
        o = append_str(out, o, max, "Seccomp_filters:\t0\n", -1); handled = 1;
      } else if (ll >= 11 && starts(line, "NoNewPrivs:")) {
        o = append_str(out, o, max, "NoNewPrivs:\t0\n", -1); handled = 1;
      }
      if (!handled && ll > 0) {
        o = append_str(out, o, max, line, ll);
        o = append_str(out, o, max, "\n", 1);
      }
      ls = i + 1;
    }
  }
  return o;
}

static long build_fake_environ(long pid, char *out, long max) {
  char real[65536];
  char path[80];
  make_proc_path(path, sizeof(path), pid, "/environ");
  long n = read_file(path, real, sizeof(real));
  if (n <= 0) return -1;
  long o = 0;
  long start = 0;
  for (long i = 0; i <= n; i++) {
    if (i == n || real[i] == 0) {
      long ll = i - start;
      if (ll > 0 && !(ll >= 10 && starts(real + start, "LD_PRELOAD"))) {
        for (long j = 0; j < ll && o < max - 1; j++) out[o++] = real[start + j];
        out[o++] = 0;
      }
      start = i + 1;
    }
  }
  out[o] = 0;
  return o;
}

static long read_tracee(long pid, u64 addr, char *buf, long max) {
  struct iovec local;
  struct iovec remote;
  local.iov_base = buf;
  local.iov_len = max;
  remote.iov_base = (void *)addr;
  remote.iov_len = max;
  return sys6(SYS_process_vm_readv, pid, (long)&local, 1, (long)&remote, 1, 0);
}

static int is_maps_path(const char *p) {
  if (seq(p, "/proc/self/maps") == 0) return 1;
  if (starts(p, "/proc/") && starts(p + 6, "self/")) return 0;
  long i = 6;
  if (p[i] < '0' || p[i] > '9') return 0;
  while (p[i] >= '0' && p[i] <= '9') i++;
  return seq(p + i, "/maps") == 0;
}

static int is_status_path(const char *p) {
  if (seq(p, "/proc/self/status") == 0) return 1;
  if (!starts(p, "/proc/")) return 0;
  long i = 6;
  if (p[i] < '0' || p[i] > '9') return 0;
  while (p[i] >= '0' && p[i] <= '9') i++;
  return seq(p + i, "/status") == 0;
}

static int is_wchan_path(const char *p) {
  if (seq(p, "/proc/self/wchan") == 0) return 1;
  if (!starts(p, "/proc/")) return 0;
  long i = 6;
  if (p[i] < '0' || p[i] > '9') return 0;
  while (p[i] >= '0' && p[i] <= '9') i++;
  return seq(p + i, "/wchan") == 0;
}

static int is_environ_path(const char *p) {
  return seq(p, "/proc/self/environ") == 0;
}

static int send_continue(long listener, struct seccomp_notif *req) {
  struct seccomp_notif_resp r;
  r.id = req->id;
  r.val = 0;
  r.error = 0;
  r.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
  return (int)sys6(SYS_ioctl, listener, (long)SECCOMP_IOCTL_NOTIF_SEND, (long)&r, 0, 0, 0);
}

static int send_value(long listener, struct seccomp_notif *req, long value, int error) {
  struct seccomp_notif_resp r;
  r.id = req->id;
  r.val = value;
  r.error = error;
  r.flags = 0;
  return (int)sys6(SYS_ioctl, listener, (long)SECCOMP_IOCTL_NOTIF_SEND, (long)&r, 0, 0, 0);
}

static int send_fake_file(long listener, struct seccomp_notif *req, const char *data, long len) {
  long fd = sys6(SYS_memfd_create, (long)"apu-fake", 0, 0, 0, 0, 0);
  if (fd < 0) return send_continue(listener, req);
  write_all(fd, data, len);
  sys6(SYS_lseek, fd, 0, SEEK_SET, 0, 0, 0);
  struct seccomp_notif_addfd add;
  add.id = req->id;
  add.flags = SECCOMP_ADDFD_FLAG_SEND;
  add.srcfd = (u32)fd;
  add.newfd = 0;
  add.newfd_flags = 0;
  long rc = sys6(SYS_ioctl, listener, (long)SECCOMP_IOCTL_NOTIF_ADDFD, (long)&add, 0, 0, 0);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
  if (rc < 0) return send_continue(listener, req);
  return 0;
}

struct k_sigaction {
  void (*handler)(int);
  unsigned long flags;
  void (*restorer)(void);
  unsigned long mask;
};

static void sigreturn_restorer(void) {
  sys6(SYS_rt_sigreturn, 0, 0, 0, 0, 0, 0);
}

/* Minimal kernel signal-context layout (x86_64). */
struct sigcontext_x86_64 {
  u64 r8, r9, r10, r11, r12, r13, r14, r15;
  u64 rdi, rsi, rbp, rsp, rbx, rdx, rax, rcx;
  u64 rip, cs, eflags, sp_at_signal, ss;
  u64 err, trapno, oldmask, cr2;
  u64 fpstate;
  u64 reserved[8];
};

struct ucontext_x86_64 {
  u64 uc_flags;
  void *uc_link;
  struct { void *ss_sp; int ss_flags; u32 pad; u64 ss_size; } uc_stack;
  struct sigcontext_x86_64 uc_mcontext;
};

struct siginfo_min {
  int si_signo;
  int si_errno;
  int si_code;
  int pad;
  void *si_addr;
};

static int skip_traps = 0;
static int trap_count = 0;

static int mode_skip_traps(void) {
  char buf[32];
  long n = read_file("/data/local/tmp/apu_shield_mode", buf, sizeof(buf));
  if (n < 4) return 0;
  if (starts(buf, "skip")) return 1;
  return 0;
}

static void trap_handler(int sig, struct siginfo_min *info, struct ucontext_x86_64 *uc) {
  u64 rip = uc ? uc->uc_mcontext.rip : 0;
  log_value("shield-trap-sig", sig);
  if (info) {
    log_value("shield-trap-code", info->si_code);
    log_value("shield-trap-addr", (long)(unsigned long)info->si_addr);
  }
  log_value("shield-trap-rip", (long)rip);
  const unsigned char *code = (const unsigned char *)(unsigned long)rip;
  if (rip) log_hex("shield-trap-bytes", code, 8);
  /* Experimental: only step over a deliberate ud2 (0f 0b). Skipping other
   * signals corrupts control flow (SIGABRT/SIGSEGV carry no instruction
   * boundary), so those still hang for inspection. */
  if (skip_traps && rip && sig == SIGILL && code[0] == 0x0f && code[1] == 0x0b && trap_count++ < 64) {
    uc->uc_mcontext.rip = rip + 2;
    log_value("shield-trap-skip", (long)uc->uc_mcontext.rip);
    return;
  }
  log_value("shield-hang", sig);
  for (;;) sys6(SYS_pause, 0, 0, 0, 0, 0, 0);
}

static void raw_sigaction(int sig, struct k_sigaction *sa) {
  sys6(SYS_rt_sigaction, sig, (long)sa, 0, 8, 0, 0);
}

static void install_trap_handler(int sig) {
  struct k_sigaction sa;
  sa.handler = (void (*)(int))trap_handler;
  sa.flags = SA_RESTORER | SA_SIGINFO;
  sa.restorer = sigreturn_restorer;
  sa.mask = 0;
  raw_sigaction(sig, &sa);
}

extern void *dlsym(void *handle, const char *symbol);
typedef int (*prop_get_fn)(const char *, char *);
static prop_get_fn real_prop_get = 0;

extern char **environ;

static void patch_stack_auxv(void) {
  char **e = environ;
  if (!e) return;
  while (*e) e++;
  e++;
  unsigned long *aux = (unsigned long *)e;
  for (long i = 0; i < 256 && aux[i] != 0; i += 2) {
    unsigned long type = aux[i];
    if (type == 16 /* AT_HWCAP */) aux[i + 1] = 0x0000000007b0dd7fUL;
    else if (type == 26 /* AT_HWCAP2 */) aux[i + 1] = 0x1UL;
    else if (type == 15 /* AT_PLATFORM */) {
      char *p = (char *)aux[i + 1];
      if (p) {
        const char *m = "aarch64";
        for (int j = 0; j < 8; j++) p[j] = m[j];
      }
    }
  }
}

static const char *prop_spoof(const char *name) {
  if (seq(name, "ro.debuggable") == 0) return "0";
  if (seq(name, "ro.dalvik.vm.native.bridge") == 0) return "";
  if (seq(name, "ro.enable.native.bridge.exec") == 0) return "0";
  if (seq(name, "ro.product.cpu.abi") == 0) return "arm64-v8a";
  if (seq(name, "ro.product.cpu.abilist") == 0) return "arm64-v8a,armeabi-v7a,armeabi";
  if (seq(name, "ro.product.cpu.abilist64") == 0) return "arm64-v8a";
  if (seq(name, "ro.product.cpu.abilist32") == 0) return "armeabi-v7a,armeabi";
  if (seq(name, "ro.dalvik.vm.isa.arm64") == 0) return "arm64";
  if (seq(name, "ro.dalvik.vm.isa.arm") == 0) return "arm";
  if (seq(name, "ro.build.fingerprint") == 0) return "Xiaomi/redmi_note8/whyred:11/RKQ1.201217.002/V12.5.1.0.PEIMIXM:user/release-keys";
  if (seq(name, "ro.product.model") == 0) return "Redmi Note 8";
  if (seq(name, "ro.product.manufacturer") == 0) return "Xiaomi";
  if (seq(name, "ro.product.brand") == 0) return "Xiaomi";
  if (seq(name, "ro.build.tags") == 0) return "release-keys";
  if (seq(name, "ro.secure") == 0) return "1";
  if (seq(name, "ro.kernel.qemu") == 0) return "0";
  if (seq(name, "ro.boot.qemu") == 0) return "0";
  if (seq(name, "ro.hardware") == 0) return "qcom";
  if (seq(name, "ro.board.platform") == 0) return "msm8953";
  if (seq(name, "ro.build.type") == 0) return "user";
  if (seq(name, "ro.build.user") == 0) return "builder";
  if (seq(name, "ro.build.host") == 0) return "buildhost";
  if (seq(name, "ro.build.flavor") == 0) return "whyred-user";
  if (seq(name, "ro.product.name") == 0) return "whyred";
  if (seq(name, "ro.product.device") == 0) return "whyred";
  if (seq(name, "ro.product.board") == 0) return "msm8953";
  return 0;
}

static int prop_interesting(const char *name) {
  return find_sub(name, "native.bridge") || find_sub(name, "cpu.abi") ||
         find_sub(name, "abilist") || find_sub(name, "isa.arm") ||
         find_sub(name, "qemu") || find_sub(name, "fingerprint") ||
         find_sub(name, "product.model") || find_sub(name, "product.manufacturer") ||
         find_sub(name, "product.brand") || find_sub(name, "build.tags") ||
         find_sub(name, "debuggable") || find_sub(name, "secure") ||
         find_sub(name, "hardware") || find_sub(name, "board") ||
         find_sub(name, "dalvik.vm.isa");
}

int __system_property_get(const char *name, char *value) {
  const char *spoof = prop_spoof(name);
  if (spoof) {
    long len = (long)slen(spoof);
    if (len > 91) len = 91;
    for (long i = 0; i < len; i++) value[i] = spoof[i];
    value[len] = 0;
    log_path("shield-prop-spoof", name);
    return (int)len;
  }
  if (prop_interesting(name)) log_path("shield-prop", name);
  if (!real_prop_get) real_prop_get = (prop_get_fn)dlsym((void *)-1, "__system_property_get");
  if (real_prop_get) return real_prop_get(name, value);
  if (value) value[0] = 0;
  return 0;
}

typedef char *(*getenv_fn)(const char *);
static getenv_fn real_getenv = 0;

char *getenv(const char *name) {
  if (name && (starts(name, "LD_PRELOAD") || starts(name, "WRAP") ||
               starts(name, "FRIDA") || starts(name, "MAGISK"))) return 0;
  if (!real_getenv) real_getenv = (getenv_fn)dlsym((void *)-1, "getenv");
  return real_getenv ? real_getenv(name) : 0;
}

char *secure_getenv(const char *name) {
  return getenv(name);
}

struct utsname_buf {
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

int uname(void *buf) {
  long rc = sys6(63, (long)buf, 0, 0, 0, 0, 0);
  if (rc == 0 && buf) {
    struct utsname_buf *u = (struct utsname_buf *)buf;
    static int logs = 0;
    if (logs < 4) { log_path("shield-uname", u->machine); logs++; }
    const char *m = "aarch64";
    for (long i = 0; i < 64 && m[i]; i++) u->machine[i] = m[i];
    u->machine[7] = 0;
  }
  return (int)rc;
}

static unsigned long aux_cache[128];
static int aux_loaded = 0;

static void load_auxv(void) {
  if (aux_loaded) return;
  aux_loaded = 1;
  long n = read_file("/proc/self/auxv", (char *)aux_cache, sizeof(aux_cache));
  if (n <= 0) return;
  for (long i = 0; i + 16 <= n; i += 16) {
    unsigned long type = *(unsigned long *)((char *)aux_cache + i);
    (void)type;
  }
}

static unsigned long aux_value(unsigned long type) {
  static const char platform[] = "aarch64";
  if (type == 15 /* AT_PLATFORM */) {
    static int logs = 0;
    if (logs < 4) { log_value("shield-getauxval-platform", (long)type); logs++; }
    return (unsigned long)platform;
  }
  if (type == 16 /* AT_HWCAP */) {
    static int logs = 0;
    if (logs < 4) { log_value("shield-getauxval-hwcap", (long)type); logs++; }
    return 0x0000000007b0dd7fUL;
  }
  if (type == 26 /* AT_HWCAP2 */) return 0x0000000000000001UL;
  load_auxv();
  for (long i = 0; i + 16 <= (long)sizeof(aux_cache); i += 16) {
    unsigned long t = aux_cache[i / 8];
    unsigned long v = aux_cache[i / 8 + 1];
    if (t == 0) break;
    if (t == type) return v;
  }
  return 0;
}

unsigned long getauxval(unsigned long type) {
  return aux_value(type);
}

unsigned long __getauxval(unsigned long type) {
  return aux_value(type);
}

static long build_fake_auxv(long pid, char *out, long max) {
  char path[80];
  char real[2048];
  make_proc_path(path, sizeof(path), pid, "/auxv");
  long n = read_file(path, real, sizeof(real));
  if (n <= 0) return -1;
  if (n > max) n = max;
  for (long i = 0; i < n; i++) out[i] = real[i];
  for (long i = 0; i + 16 <= n; i += 16) {
    unsigned long type = *(unsigned long *)(out + i);
    if (type == 0) break;
    if (type == 16) *(unsigned long *)(out + i + 8) = 0x0000000007b0dd7fUL;
    else if (type == 26) *(unsigned long *)(out + i + 8) = 0x1UL;
  }
  return n;
}

static int is_auxv_path(const char *p) {
  if (seq(p, "/proc/self/auxv") == 0) return 1;
  if (!starts(p, "/proc/")) return 0;
  long i = 6;
  if (p[i] < '0' || p[i] > '9') return 0;
  while (p[i] >= '0' && p[i] <= '9') i++;
  return seq(p + i, "/auxv") == 0;
}

static void dump_debug(const char *name, const char *data, long len) {
  char path[128];
  long n = append_str(path, 0, sizeof(path), "/data/local/tmp/apu_last_", -1);
  n = append_str(path, n, sizeof(path), name, -1);
  long fd = sys6(SYS_openat, AT_FDCWD, (long)path,
                 O_WRONLY | O_CREAT | O_TRUNC, 0644, 0, 0);
  if (fd < 0) return;
  write_all(fd, data, len);
  sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static void handle_notif(long listener, struct seccomp_notif *req) {
  int nr = req->data.nr;
  long tgid = tgid_of((long)req->pid);

  if (nr == 62 || nr == 234 || nr == 200 || nr == 129 || nr == 240) {
    /* kill / tgkill / tkill / rt_sigqueueinfo / rt_tgsigqueueinfo */
    long sig;
    if (nr == 234 || nr == 240) sig = (long)req->data.args[2];
    else sig = (long)req->data.args[1];
    long target = (long)req->data.args[0];
    int self_target = (target == tgid || target == -tgid || target == (long)req->pid);
    if (self_target && (sig == 9 || sig == 6 || sig == 7 || sig == 11)) {
      static int kill_logs = 0;
      if (kill_logs < 4) {
        kill_logs++;
        char scpath[80];
        make_proc_path(scpath, sizeof(scpath), (long)req->pid, "/syscall");
        long n = read_file(scpath, path_buf, sizeof(path_buf));
        if (n > 0) log_path("shield-kill-syscall", path_buf);
        /* The last two whitespace-separated tokens are SP and PC. */
        long sp = 0;
        long count = 0;
        for (long i = 0; i < n; i++) {
          if (path_buf[i] == ' ') {
            count++;
            if (count == 7) {
              char *p = path_buf + i + 1;
              while (*p == ' ') p++;
              long v = 0;
              if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
              while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
                long d = (*p <= '9') ? (*p - '0') : ((*p | 0x20) - 'a' + 10);
                v = v * 16 + d;
                p++;
              }
              sp = v;
              break;
            }
          }
        }
        log_value("shield-kill-sp", sp);
        if (sp > 0) {
          unsigned char sbuf[128];
          long got = read_tracee((long)req->pid, (u64)sp, (char *)sbuf, sizeof(sbuf));
          if (got > 0) log_hex("shield-kill-stack", sbuf, got < 128 ? got : 128);
        }
      }
      log_value("shield-kill-blocked", tgid);
      send_value(listener, req, 0, 0);
      return;
    }
    send_continue(listener, req);
    return;
  }
  if (nr == 231) { /* exit_group */
    log_value("shield-exit-blocked", tgid);
    send_value(listener, req, 0, 0);
    return;
  }
  if (nr == 257 || nr == 437 || nr == 2) { /* openat / openat2 / open */
    u64 path_addr = (nr == 2) ? req->data.args[0] : req->data.args[1];
    long n = read_tracee((long)req->pid, path_addr, path_buf, sizeof(path_buf) - 1);
    if (n <= 0) { send_continue(listener, req); return; }
    if (n >= (long)sizeof(path_buf)) n = sizeof(path_buf) - 1;
    path_buf[n] = 0;
    if (is_maps_path(path_buf)) {
      long len = build_fake_maps(tgid, content_buf, MAP_SIZE);
      if (len > 0) { dump_debug("maps", content_buf, len); log_path("shield-fake-maps", path_buf); send_fake_file(listener, req, content_buf, len); return; }
    } else if (is_status_path(path_buf)) {
      long len = build_fake_status(tgid, content_buf, MAP_SIZE);
      if (len > 0) { dump_debug("status", content_buf, len); log_path("shield-fake-status", path_buf); send_fake_file(listener, req, content_buf, len); return; }
    } else if (is_auxv_path(path_buf)) {
      long len = build_fake_auxv(tgid, content_buf, MAP_SIZE);
      if (len > 0) { log_path("shield-fake-auxv", path_buf); send_fake_file(listener, req, content_buf, len); return; }
    } else if (is_wchan_path(path_buf)) {
      log_path("shield-fake-wchan", path_buf);
      send_fake_file(listener, req, "futex_wait\n", 11);
      return;
    } else if (is_environ_path(path_buf)) {
      long len = build_fake_environ(tgid, content_buf, MAP_SIZE);
      if (len > 0) { log_path("shield-fake-environ", path_buf); send_fake_file(listener, req, content_buf, len); return; }
    } else if (seq(path_buf, "/proc/cpuinfo") == 0) {
      log_path("shield-fake-cpuinfo", path_buf);
      send_fake_file(listener, req, CPUINFO_FAKE, (long)sizeof(CPUINFO_FAKE) - 1);
      return;
    } else if (seq(path_buf, "/sys/devices/system/cpu/online") == 0 ||
               seq(path_buf, "/sys/devices/system/cpu/present") == 0 ||
               seq(path_buf, "/sys/devices/system/cpu/possible") == 0) {
      log_path("shield-fake-cpulist", path_buf);
      send_fake_file(listener, req, "0-7\n", 4);
      return;
    } else if (seq(path_buf, "/system/build.prop") == 0 ||
               seq(path_buf, "/vendor/build.prop") == 0) {
      log_path("shield-fake-buildprop", path_buf);
      send_fake_file(listener, req, BUILD_PROP_FAKE, (long)sizeof(BUILD_PROP_FAKE) - 1);
      return;
    }
    send_continue(listener, req);
    return;
  }
  send_continue(listener, req);
}

static void supervisor_loop(long listener) {
  struct seccomp_notif req;
  for (;;) {
    for (long i = 0; i < (long)sizeof(req); i++) ((char *)&req)[i] = 0;
    long rc = sys6(SYS_ioctl, listener, (long)SECCOMP_IOCTL_NOTIF_RECV, (long)&req, 0, 0, 0);
    if (rc < 0) continue;
    handle_notif(listener, &req);
  }
}

static int recv_listener(int sock) {
  char data;
  char control[128];
  struct iovec iov;
  struct msghdr msg;
  iov.iov_base = &data;
  iov.iov_len = 1;
  for (long i = 0; i < (long)sizeof(msg); i++) ((char *)&msg)[i] = 0;
  for (long i = 0; i < (long)sizeof(control); i++) control[i] = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  long rc = sys6(SYS_recvmsg, sock, (long)&msg, 0, 0, 0, 0);
  if (rc <= 0) return -1;
  struct cmsghdr *cm = (struct cmsghdr *)control;
  if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) return -1;
  return *(int *)CMSG_DATA(cm);
}

static void child_main(int sock) {
  sys6(SYS_prctl, PR_SET_NAME, (long)"kworker/u4:1", 0, 0, 0, 0);
  long listener = recv_listener(sock);
  sys6(SYS_close, sock, 0, 0, 0, 0, 0);
  if (listener < 0) {
    log_value("shield-child-no-listener", listener);
    sys6(60 /* exit */, 0, 0, 0, 0, 0, 0);
  }
  log_value("shield-child-listener", listener);
  supervisor_loop(listener);
  sys6(60, 0, 0, 0, 0, 0, 0);
}

static int send_listener(int sock, long listener) {
  char data = 'F';
  char control[CMSG_SPACE(4)];
  for (long i = 0; i < (long)sizeof(control); i++) control[i] = 0;
  struct iovec iov;
  struct msghdr msg;
  iov.iov_base = &data;
  iov.iov_len = 1;
  for (long i = 0; i < (long)sizeof(msg); i++) ((char *)&msg)[i] = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  struct cmsghdr *cm = (struct cmsghdr *)control;
  cm->cmsg_len = CMSG_LEN(4);
  cm->cmsg_level = SOL_SOCKET;
  cm->cmsg_type = SCM_RIGHTS;
  *(int *)CMSG_DATA(cm) = (int)listener;
  return (int)sys6(SYS_sendmsg, sock, (long)&msg, 0, 0, 0, 0);
}

static struct sock_filter FILTER[] = {
  {0x20, 0, 0, 4},                         /* 0: A = arch */
  {0x15, 0, 11, AUDIT_ARCH_X86_64},        /* 1: x86_64 ? 2 : 13 */
  {0x20, 0, 0, 0},                         /* 2: A = nr */
  {0x15, 8, 0, 2},                         /* 3: open -> 12 */
  {0x15, 7, 0, 62},                        /* 4: kill -> 12 */
  {0x15, 6, 0, 200},                       /* 5: tkill -> 12 */
  {0x15, 5, 0, 234},                       /* 6: tgkill -> 12 */
  {0x15, 4, 0, 257},                       /* 7: openat -> 12 */
  {0x15, 3, 0, 437},                       /* 8: openat2 -> 12 */
  {0x15, 2, 0, 231},                       /* 9: exit_group -> 12 */
  {0x15, 1, 0, 129},                       /* 10: rt_sigqueueinfo -> 12 */
  {0x15, 0, 1, 240},                       /* 11: rt_tgsigqueueinfo -> 12 else 13 */
  {0x06, 0, 0, SECCOMP_RET_USER_NOTIF},    /* 12: notify */
  {0x06, 0, 0, SECCOMP_RET_ALLOW},         /* 13: allow */
};

__attribute__((constructor)) static void apu_shield_init(void) {
  patch_stack_auxv();
  int sv[2];
  long rc = sys6(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)sv, 0, 0);
  if (rc < 0) { log_value("shield-socketpair", rc); return; }
  long child = sys6(SYS_fork, 0, 0, 0, 0, 0, 0);
  if (child == 0) {
    sys6(SYS_close, sv[0], 0, 0, 0, 0, 0);
    child_main((int)sv[1]);
    sys6(60, 0, 0, 0, 0, 0, 0);
  }
  sys6(SYS_close, sv[1], 0, 0, 0, 0, 0);
  if (child < 0) { log_value("shield-fork", child); return; }

  sys6(SYS_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0, 0);
  sys6(SYS_prctl, PR_SET_PTRACER, child, 0, 0, 0, 0);
  sys6(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
  skip_traps = mode_skip_traps();
  log_value("shield-skip-traps", skip_traps);
  install_trap_handler(SIGILL);
  install_trap_handler(SIGSEGV);
  install_trap_handler(SIGABRT);
  install_trap_handler(SIGBUS);

  struct sock_fprog prog;
  prog.len = (u16)(sizeof(FILTER) / sizeof(FILTER[0]));
  prog.filter = FILTER;
  long listener = sys6(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER,
                       (long)&prog, 0, 0, 0);
  if (listener < 0) {
    listener = sys6(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_NEW_LISTENER, (long)&prog, 0, 0, 0);
  }
  if (listener < 0) {
    log_value("shield-seccomp", listener);
    sys6(SYS_close, sv[0], 0, 0, 0, 0, 0);
    return;
  }
  long sent = send_listener((int)sv[0], listener);
  log_value("shield-listener", listener);
  log_value("shield-sendmsg", sent);
  sys6(SYS_close, listener, 0, 0, 0, 0, 0);
  sys6(SYS_close, sv[0], 0, 0, 0, 0, 0);
}
