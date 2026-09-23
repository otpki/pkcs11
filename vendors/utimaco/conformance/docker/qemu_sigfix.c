/*
 * qemu-i386 signal shim for the Utimaco CryptoServer simulator (bl_sim5).
 *
 * The simulator is a 32-bit i386 ELF; on arm64 Docker Desktop it executes
 * under qemu-user-i386 binfmt. qemu-user can neither create POSIX timers that
 * deliver guest realtime signals >= 61 nor deliver those signals at all, so
 * the simulator's SMOS scheduler tick (signal 63) never fires and the firmware
 * parks immediately after listen() without ever calling accept().
 *
 * This preload remaps guest signals 61..64 onto 57..60, which qemu-i386
 * handles correctly and which the simulator's modules never otherwise use.
 * LD_PRELOAD is scoped to the bl_sim5 invocation only; preloading it into the
 * 64-bit administration tools is harmless but produces an ELF-class warning.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

static int sub_signo(int s) { return (s >= 61 && s <= 64) ? s - 4 : s; }
static int orig_signo(int s) { return (s >= 57 && s <= 60) ? s + 4 : s; }

static void translate_set(sigset_t *s) {
  int i;
  for (i = 61; i <= 64; i++)
    if (sigismember(s, i) == 1) sigaddset(s, i - 4);
}

int sigaction(int signo, const struct sigaction *act, struct sigaction *old) {
  static int (*real)(int, const struct sigaction *, struct sigaction *);
  if (!real) real = dlsym(RTLD_NEXT, "sigaction");
  return real(sub_signo(signo), act, old);
}

sighandler_t signal(int signo, sighandler_t h) {
  static sighandler_t (*real)(int, sighandler_t);
  if (!real) real = dlsym(RTLD_NEXT, "signal");
  return real(sub_signo(signo), h);
}

int timer_create(clockid_t clk, struct sigevent *sev, timer_t *tid) {
  static int (*real)(clockid_t, struct sigevent *, timer_t *);
  struct sigevent copy;
  if (!real) real = dlsym(RTLD_NEXT, "timer_create");
  if (sev && (sev->sigev_notify == SIGEV_SIGNAL || sev->sigev_notify == SIGEV_THREAD_ID)) {
    copy = *sev;
    copy.sigev_signo = sub_signo(copy.sigev_signo);
    sev = &copy;
  }
  return real(clk, sev, tid);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
  static int (*real)(int, const sigset_t *, sigset_t *);
  sigset_t copy;
  if (!real) real = dlsym(RTLD_NEXT, "sigprocmask");
  if (set) { copy = *set; translate_set(&copy); set = &copy; }
  return real(how, set, old);
}

int sigwait(const sigset_t *set, int *sig) {
  static int (*real)(const sigset_t *, int *);
  sigset_t copy;
  int r;
  if (!real) real = dlsym(RTLD_NEXT, "sigwait");
  copy = *set; translate_set(&copy);
  r = real(&copy, sig);
  if (r == 0 && sig) *sig = orig_signo(*sig);
  return r;
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info) {
  static int (*real)(const sigset_t *, siginfo_t *);
  sigset_t copy; int r;
  if (!real) real = dlsym(RTLD_NEXT, "sigwaitinfo");
  copy = *set; translate_set(&copy);
  r = real(&copy, info);
  if (r > 0) { if (info) info->si_signo = orig_signo(info->si_signo); r = orig_signo(r); }
  return r;
}

int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *ts) {
  static int (*real)(const sigset_t *, siginfo_t *, const struct timespec *);
  sigset_t copy; int r;
  if (!real) real = dlsym(RTLD_NEXT, "sigtimedwait");
  copy = *set; translate_set(&copy);
  r = real(&copy, info, ts);
  if (r > 0) { if (info) info->si_signo = orig_signo(info->si_signo); r = orig_signo(r); }
  return r;
}

int sigsuspend(const sigset_t *set) {
  static int (*real)(const sigset_t *);
  sigset_t copy;
  if (!real) real = dlsym(RTLD_NEXT, "sigsuspend");
  copy = *set; translate_set(&copy);
  return real(&copy);
}

int raise(int sig) { return kill(getpid(), sub_signo(sig)); }

int kill(pid_t pid, int sig) {
  static int (*real)(pid_t, int);
  if (!real) real = dlsym(RTLD_NEXT, "kill");
  return real(pid, sub_signo(sig));
}

int pthread_kill(unsigned long t, int sig) {
  static int (*real)(unsigned long, int);
  if (!real) real = dlsym(RTLD_NEXT, "pthread_kill");
  return real(t, sub_signo(sig));
}

int sigqueue(pid_t pid, int sig, const union sigval val) {
  static int (*real)(pid_t, int, const union sigval);
  if (!real) real = dlsym(RTLD_NEXT, "sigqueue");
  return real(pid, sub_signo(sig), val);
}
