"""Exercise the deployed native helper against the Linux Binder wire layout."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class BinderPatchTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                         "requires the existing Linux C compiler")
    def test_socket_cookie_width_and_invalid_lengths(self):
        patch = (Path(__file__).resolve().parents[1] / "deploy" /
                 "qemu-android-netd-sockets.patch").read_text()
        added = "\n".join(line[1:] for line in patch.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        body = added.split("case SO_COOKIE: {", 1)[1].split("\n        }", 1)[0]
        body = body.replace("            break;", "            return 0;")
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#define TARGET_EFAULT 14
#define TARGET_EINVAL 22
static int fail_socket;
static int cookie_get(int fd,int level,int name,void *out,socklen_t *size) {
    uint64_t value=UINT64_C(0x123456789abcdef0);
    assert(*size==8);
    if(fail_socket){errno=ENOPROTOOPT;return -1;}
    memcpy(out,&value,8);*size=8;return 0;
}
static int get_errno(int ret){return ret<0 ? -errno : ret;}
static int put64(uint64_t v,uintptr_t p){memcpy((void*)p,&v,8);return 0;}
static int put32(uint32_t v,uintptr_t p){memcpy((void*)p,&v,4);return 0;}
#define getsockopt cookie_get
#define get_user_u32(v,p) ((v=*(int32_t*)(p)),0)
#define put_user_u64 put64
#define put_user_u32 put32
static long read_cookie(uintptr_t optval_addr,uintptr_t optlen) {
    int sockfd=1,len;long ret;socklen_t lv;
BODY
}
int main(void) {
    int32_t sizes[]={-1,0,7,8,16};
    for(int i=0;i<5;i++) {
        int32_t len=sizes[i];unsigned char out[16];memset(out,0xcd,sizeof(out));
        long ret=read_cookie((uintptr_t)out,(uintptr_t)&len);
        if(sizes[i]<8) {assert(ret==-22);for(int k=0;k<16;k++)assert(out[k]==0xcd);}
        else {uint64_t value;memcpy(&value,out,8);assert(!ret && len==8);
              assert(value==UINT64_C(0x123456789abcdef0));}
        for(int k=8;k<16;k++)assert(out[k]==0xcd);
    }
    fail_socket=1;int32_t len=8;unsigned char out[16];memset(out,0xcd,sizeof(out));
    assert(read_cookie((uintptr_t)out,(uintptr_t)&len)==-ENOPROTOOPT);
    assert(out[0]==0xcd && len==8);
    return 0;
}
'''.replace("BODY", body)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "socket_cookie.c"
            binary = Path(folder) / "socket_cookie"
            source.write_text(harness)
            subprocess.run([shutil.which("cc"), "-O2", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                         "requires the existing Linux C compiler")
    def test_guest_threads_use_linux_user_task_ids(self):
        patch = (Path(__file__).resolve().parents[1] / "deploy" /
                 "qemu-android-guest-tasks.patch").read_text()
        added = "\n".join(line[1:] for line in patch.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        start = added.index("static bool apu_guest_task_dir")
        entry = added.index("static bool apu_guest_task_entry")
        brace = added.index("{", entry)
        depth = 1
        end = brace + 1
        while depth:
            depth += (added[end] == "{") - (added[end] == "}")
            end += 1
        helper = added[start:end]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
static bool profile=true;
static const char *resolved="/proc/42/task";
static int fake_access(const char *p, int mode) { return profile ? 0 : -1; }
static pid_t fake_getpid(void) { return 42; }
static ssize_t fake_readlink(const char *p, char *buf, size_t n) {
    assert(strcmp(p,"/proc/self/fd/3")==0);
    size_t len=strlen(resolved); if(len>n)len=n; memcpy(buf,resolved,len); return len;
}
#define access fake_access
#define getpid fake_getpid
#define readlink fake_readlink
typedef struct { long ts_tid; } TaskState;
typedef struct CPUState { int thread_id; void *opaque; struct CPUState *next; } CPUState;
static CPUState *head;
#define CPU_FOREACH(cpu) for (cpu=head; cpu; cpu=cpu->next)
static void rcu_read_lock(void) {}
static void rcu_read_unlock(void) {}
HELPER
int main(void) {
    assert(apu_guest_task_dir(3));
    resolved="/proc/43/task"; assert(!apu_guest_task_dir(3));
    resolved="/tmp/task"; assert(!apu_guest_task_dir(3));
    resolved="/proc/42/task"; profile=false; assert(!apu_guest_task_dir(3));
    TaskState a={42}, b={57};
    CPUState second={0,&b,0}, first={999,&a,&second}; head=&first;
    assert(apu_guest_task_entry("42"));
    assert(apu_guest_task_entry("57"));
    assert(!apu_guest_task_entry("999"));
    assert(!apu_guest_task_entry("58"));
    assert(apu_guest_task_entry("."));
    assert(apu_guest_task_entry(".."));
    assert(apu_guest_task_entry("other"));
    head=0;
    assert(!apu_guest_task_entry("42"));
    return 0;
}
'''.replace("HELPER", helper)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "guest_threads.c"
            binary = Path(folder) / "guest_threads"
            source.write_text(harness)
            subprocess.run([shutil.which("cc"), "-O2", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                         "requires the existing Linux C compiler and Binder header")
    def test_kernel_command_sizes_and_truncated_buffers(self):
        patch = (Path(__file__).resolve().parents[1] / "deploy" / "qemu-binder.patch").read_text()
        added = "\n".join(line[1:] for line in patch.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        helper = added[added.index("static uint64_t apu_untag_ptr"):
                       added.index("static abi_long do_binder_write_read")]
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/android/binder.h>
HELPER
int main(void) {
    const uint32_t commands[] = {
        BC_TRANSACTION, BC_REPLY, BC_ACQUIRE_RESULT, BC_FREE_BUFFER,
        BC_INCREFS, BC_ACQUIRE, BC_RELEASE, BC_DECREFS, BC_INCREFS_DONE,
        BC_ACQUIRE_DONE, BC_ATTEMPT_ACQUIRE, BC_REGISTER_LOOPER,
        BC_ENTER_LOOPER, BC_EXIT_LOOPER, BC_REQUEST_DEATH_NOTIFICATION,
        BC_CLEAR_DEATH_NOTIFICATION, BC_DEAD_BINDER_DONE,
        BC_TRANSACTION_SG, BC_REPLY_SG
    };
    const uint64_t tagged = UINT64_C(0xab00000012345000);
    const uint64_t untagged = UINT64_C(0x12345000);
    assert(sizeof(struct binder_handle_cookie) == 12);
    assert(offsetof(struct binder_handle_cookie, cookie) == 4);
    for (size_t k = 0; k < sizeof(commands)/sizeof(commands[0]); k++) {
        size_t total = 4 + _IOC_SIZE(commands[k]);
        for (size_t n = 0; n <= total; n++) {
            unsigned char *b = malloc(total + 16);
            memset(b, 0, total + 16);
            memcpy(b, &commands[k], 4);
            size_t offsets[2] = {SIZE_MAX, SIZE_MAX};
            switch (k) {
            case 0: case 1: case 17: case 18: offsets[0]=48; offsets[1]=56; break;
            case 3: offsets[0]=0; break;
            }
            if (total>4) memset(b+4, 0xab, total-4);
            for (int i=0; i<2; i++)
                if (offsets[i]!=SIZE_MAX) memcpy(b+4+offsets[i], &tagged, 8);
            memset(b+n, 0xcd, total + 16 - n);
            unsigned char before[128]; memcpy(before, b, total + 16);
            apu_untag_binder_write_buf(b, n);
            assert(memcmp(b+n, before+n, total + 16 - n) == 0);
            if (n == total) for (int i=0; i<2; i++)
                if (offsets[i]!=SIZE_MAX) memcpy(before+4+offsets[i], &untagged, 8);
            assert(memcmp(b, before, n) == 0);
            free(b);
        }
    }
    return 0;
}
'''.replace("HELPER", helper)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "binder_boundary.c"
            binary = Path(folder) / "binder_boundary"
            source.write_text(harness)
            subprocess.run([shutil.which("cc"), "-O2", "-D_FORTIFY_SOURCE=3",
                            str(source), "-o", str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)
