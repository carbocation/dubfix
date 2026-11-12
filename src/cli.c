/*
 * dubfix command line: check, fix, verify.
 *
 * These commands only run the single-purpose steps in dubfix.c
 * ("dubfix step ...") in the right order and choose the folder names. Each step
 * runs as its own child process with its own log, exactly as it would when run
 * by hand. Nothing in this file talks to USB.
 */
#include "profile.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int dubfix_step(int argc,char **argv);

#define DATA_DIR "dubfix-data"
enum { MAX_FOUND=8, PATH_BYTES=512, CAPTURE_BYTES=8192, LOG_LIMIT=4*1024*1024 };

struct found { char iface[16],mac[18]; int supported; };
struct session {
    char iface[16],mac[18];
    char dir[PATH_BYTES],backup[PATH_BYTES],last[PATH_BYTES];
    char token[200],reason[256];
    int fixed;
};
struct outcome { int found,stage,pulse,stored; };

static volatile sig_atomic_t stop_requested;
static void on_stop(int sig) { (void)sig; stop_requested=1; }

static void say(const char *format,...)
{
    va_list ap; va_start(ap,format); vprintf(format,ap); va_end(ap); fflush(stdout);
}

/* Run "dubfix step ARGS..." as a child. Its stdout is captured when a buffer is
 * given and discarded otherwise (the step's own transaction.log keeps it).
 * Returns the child's exit status, or -1 if it could not be run. */
static int spawn_step(char *const args[],char *capture,size_t capture_size)
{
    char self[PATH_MAX]; uint32_t self_size=sizeof(self);
    char *argv[12]; int n=0,fds[2]={-1,-1},status=0;
    if (_NSGetExecutablePath(self,&self_size)) return -1;
    argv[n++]=self; argv[n++]="step";
    for (int i=0;args[i] && n<11;i++) argv[n++]=args[i];
    argv[n]=NULL;
    if (capture) {
        if (!capture_size || pipe(fds)) return -1;
        capture[0]=0;
    }
    fflush(stdout);
    pid_t pid=fork();
    if (pid<0) {
        if (capture) { close(fds[0]); close(fds[1]); }
        return -1;
    }
    if (!pid) {
        int out=capture?fds[1]:open("/dev/null",O_WRONLY);
        if (out<0 || dup2(out,STDOUT_FILENO)<0) _exit(126);
        if (capture) close(fds[0]);
        close(out);
        execv(self,argv);
        _exit(126);
    }
    if (capture) {
        size_t used=0; char spill[512];
        close(fds[1]);
        for (;;) {
            int fits=used+1<capture_size;
            ssize_t r=read(fds[0],fits?capture+used:spill,fits?capture_size-1-used:sizeof(spill));
            if (r<0 && errno==EINTR) continue;
            if (r<=0) break;
            if (fits) used+=(size_t)r;
        }
        capture[used]=0; close(fds[0]);
    }
    while (waitpid(pid,&status,0)<0) if (errno!=EINTR) return -1;
    return WIFEXITED(status)?WEXITSTATUS(status):-1;
}
/* Replaced by the offline tests. */
static int (*run_step)(char *const args[],char *capture,size_t capture_size)=spawn_step;
static FILE *answers;

static int exists(const char *path) { struct stat st; return !lstat(path,&st); }
static char *read_text(const char *path)
{
    FILE *f=fopen(path,"r"); char *text=NULL; long size;
    if (!f) return NULL;
    if (!fseek(f,0,SEEK_END) && (size=ftell(f))>=0 && size<=LOG_LIMIT && !fseek(f,0,SEEK_SET) &&
        (text=malloc((size_t)size+1))) {
        size_t got=fread(text,1,(size_t)size,f); text[got]=0;
    }
    fclose(f);
    return text;
}
static void timestamp(char out[32])
{
    time_t now=time(NULL); struct tm utc;
    gmtime_r(&now,&utc); strftime(out,32,"%Y%m%d-%H%M%S",&utc);
}
static int field(const char *line,const char *key)
{
    const char *p=strstr(line,key);
    return p && isdigit((unsigned char)p[strlen(key)])?atoi(p+strlen(key)):-1;
}
/* Every step ends its log with one TRANSACTION STATE line. A log without it
 * means the step did not finish. */
static struct outcome parse_outcome(const char *log)
{
    struct outcome o={0,-1,-1,-1}; const char *line=NULL;
    for (const char *p=log;p && (p=strstr(p,"TRANSACTION STATE"));p++) line=p;
    if (!line) return o;
    o.found=1;
    o.stage=field(line,"stageAttempted=");
    o.pulse=field(line,"pulseAttempted=");
    o.stored=field(line,"OTPverified=");
    return o;
}
static struct outcome read_outcome(const char *dir)
{
    char path[PATH_BYTES+32]; snprintf(path,sizeof(path),"%s/transaction.log",dir);
    char *log=read_text(path); struct outcome o=parse_outcome(log);
    free(log);
    return o;
}
static void print_problems(const char *dir)
{
    char path[PATH_BYTES+32]; snprintf(path,sizeof(path),"%s/transaction.log",dir);
    char *log=read_text(path);
    for (char *line=log,*end;line && *line;line=end) {
        end=strchr(line,'\n');
        if (end) *end++=0; else end=line+strlen(line);
        if (strstr(line,"Refused") || strstr(line,"ERROR") || strstr(line,"failed")) say("  %s\n",line);
    }
    if (log) say("  Full log: %s\n",path);
    free(log);
}
/* One line of "dubfix step list" per attached D-Link 2001:b301 adapter. */
static int parse_list_line(const char *line,struct found *out)
{
    struct found f={{0},{0},0}; uint8_t mac[6];
    if (sscanf(line,"%15s hardwareMAC=%17s",f.iface,f.mac)!=2 || !strstr(line," profileHardware=")) return -1;
    f.supported=strstr(line," profileHardware=candidate")!=NULL && !dubfix_parse_mac(f.mac,mac);
    *out=f;
    return 0;
}
static int parse_list(char *text,struct found list[MAX_FOUND])
{
    int n=0;
    for (char *line=text,*end;line && *line && n<MAX_FOUND;line=end) {
        end=strchr(line,'\n');
        if (end) *end++=0; else end=line+strlen(line);
        if (!parse_list_line(line,&list[n])) n++;
    }
    return n;
}
/* Copies the rest of the line that follows "Key: " in step output. */
static int text_value(const char *text,const char *key,char *out,size_t size)
{
    const char *p=text;
    size_t key_length=strlen(key);
    while (p && *p) {
        if (!strncmp(p,key,key_length)) {
            size_t n=strcspn(p+key_length,"\n");
            if (n>=size) return -1;
            memcpy(out,p+key_length,n); out[n]=0;
            return 0;
        }
        p=strchr(p,'\n');
        if (p) p++;
    }
    return -1;
}

static int select_adapter(struct session *s,const char *want)
{
    char text[CAPTURE_BYTES]; struct found list[MAX_FOUND]; int supported=0,chosen=-1;
    char *args[]={"list",NULL};
    if (run_step(args,text,sizeof(text))<0) { say("Could not run the adapter scan.\n"); return -1; }
    int n=parse_list(text,list);
    for (int i=0;i<n;i++) {
        if (want && strcmp(want,list[i].iface)) continue;
        if (want || list[i].supported) chosen=i;
        supported+=list[i].supported;
    }
    if (want && chosen<0) {
        say("No D-Link DUB-E250 is attached as %s.\n",want); return -1;
    }
    if (!want && !supported) {
        if (n) say("Found a D-Link adapter on %s, but it is not the supported hardware (DUB-E250 A1, USB revision 3100, chip 7410).\n",list[0].iface);
        else say("No D-Link DUB-E250 found. Plug it into this Mac directly and try again.\n");
        return -1;
    }
    if (!want && supported>1) {
        say("More than one supported adapter is attached. Name the one you mean:\n");
        for (int i=0;i<n;i++) if (list[i].supported) say("  %s  (MAC %s)\n",list[i].iface,list[i].mac);
        return -1;
    }
    if (!list[chosen].supported) {
        say("%s is a D-Link adapter, but not the supported hardware (DUB-E250 A1, USB revision 3100, chip 7410).\n",list[chosen].iface);
        return -1;
    }
    snprintf(s->iface,sizeof(s->iface),"%s",list[chosen].iface);
    snprintf(s->mac,sizeof(s->mac),"%s",list[chosen].mac);
    snprintf(s->dir,sizeof(s->dir),DATA_DIR "/%s",s->mac);
    for (char *p=s->dir+sizeof(DATA_DIR);*p;p++) if (*p==':') *p='-';
    snprintf(s->backup,sizeof(s->backup),"%s/backup",s->dir);
    say("Found a DUB-E250 on %s (MAC %s).\n",s->iface,s->mac);
    return 0;
}
/* Runs one hardware step into a new, timestamped folder under the adapter's
 * data folder and leaves that folder's path in s->last. */
static int hardware_step(struct session *s,const char *step,const char *token)
{
    char stamp[32]; timestamp(stamp);
    snprintf(s->last,sizeof(s->last),"%s/%s-%s",s->dir,stamp,step);
    for (int n=2;exists(s->last) && n<100;n++)
        snprintf(s->last,sizeof(s->last),"%s/%s-%d-%s",s->dir,stamp,n,step);
    char *args[]={(char *)step,s->iface,s->backup,s->last,(char *)token,NULL};
    return run_step(args,NULL,0);
}
static int stopped(void)
{
    if (stop_requested) say("Stopped.\n");
    return stop_requested;
}
static int ensure_backup(struct session *s)
{
    char file[PATH_BYTES+32]; snprintf(file,sizeof(file),"%s/backup.bin",s->backup);
    if ((mkdir(DATA_DIR,0700) && errno!=EEXIST) || (mkdir(s->dir,0700) && errno!=EEXIST)) {
        say("Could not create %s: %s\n",s->dir,strerror(errno)); return -1;
    }
    if (exists(file)) { say("Using the backup already saved in %s.\n",s->backup); return 0; }
    if (exists(s->backup)) {
        char stamp[32],aside[PATH_BYTES+64]; timestamp(stamp);
        snprintf(aside,sizeof(aside),"%s/%s-backup-incomplete",s->dir,stamp);
        if (rename(s->backup,aside)) { say("Could not move the incomplete backup in %s aside.\n",s->backup); return -1; }
    }
    say("Saving a backup of the adapter's memory... ");
    char *args[]={"backup",s->iface,s->backup,NULL};
    int result=run_step(args,NULL,0);
    if (exists(file) && (result==0 || result==1)) { say("saved to %s\n",s->backup); return 0; }
    say("failed.\n"); print_problems(s->backup);
    return -1;
}
/* Offline: classifies the backup and derives the token that apply requires. */
static int read_plan(struct session *s)
{
    char text[CAPTURE_BYTES],kind[32]="";
    char *args[]={"plan",s->backup,NULL};
    int result=run_step(args,text,sizeof(text));
    (void)text_value(text,"Classification: ",kind,sizeof(kind));
    (void)text_value(text,"Reason: ",s->reason,sizeof(s->reason));
    if (result==0 && (!strcmp(kind,"fixable") || !strcmp(kind,"already-fixed")) &&
        !text_value(text,"Confirmation token: ",s->token,sizeof(s->token))) return 0;
    if (!strcmp(kind,"unsupported"))
        say("This adapter's memory does not have the factory layout this tool knows, so it cannot be fixed.\n"
            "  Reason: %s\n  Nothing was changed. The backup is in %s.\n",s->reason,s->backup);
    else say("The backup in %s could not be read.\n",s->backup);
    return -1;
}
/* Everything that is safe to do unasked: find the adapter, back it up, check
 * the backup, and compare the live adapter with it. */
static int examine(struct session *s,const char *want)
{
    if (select_adapter(s,want) || stopped() || ensure_backup(s) || stopped() || read_plan(s)) return -1;
    say("Checking the adapter against its backup... ");
    int result=hardware_step(s,"preflight",NULL);
    if (result) { say("failed.\n"); print_problems(s->last); return -1; }
    say("ok\n");
    s->fixed=read_outcome(s->last).stored==1;
    return stopped()?-1:0;
}
/* A write whose result is unknown must not be followed by a second write. */
static int unresolved_write(const struct session *s,char *where,size_t size)
{
    DIR *d=opendir(s->dir); struct dirent *e; int unresolved=0;
    if (!d) return 0;
    while (!unresolved && (e=readdir(d))) {
        size_t n=strlen(e->d_name);
        if (n<6 || strcmp(e->d_name+n-6,"-apply")) continue;
        snprintf(where,size,"%s/%s",s->dir,e->d_name);
        struct outcome o=read_outcome(where);
        unresolved=!o.found || o.stage!=0 || o.pulse!=0;
    }
    closedir(d);
    return unresolved;
}
static int confirmed(const struct session *s)
{
    char line[64]="",typed[64]; size_t n=0;
    const char expected[5]={s->mac[12],s->mac[13],s->mac[15],s->mac[16],0};
    say("\nReady to write the fix to %s (MAC %s).\n"
        "This permanently writes four bytes to the adapter. It cannot be undone, and a\n"
        "failed write can leave the adapter unusable. Keep the adapter plugged in and\n"
        "the Mac awake until this finishes.\n\n"
        "Type %s (the last four digits of the MAC address) to continue, or press Return to cancel: ",
        s->iface,s->mac,expected);
    if (!fgets(line,sizeof(line),answers?answers:stdin)) return 0;
    for (const char *p=line;*p;p++)
        if (!isspace((unsigned char)*p) && *p!=':') typed[n++]=(char)tolower((unsigned char)*p);
    typed[n]=0;
    return !strcmp(typed,expected);
}

static int command_check(const char *want)
{
    struct session s={0};
    if (examine(&s,want)) return 1;
    if (s.fixed) say("\nThis adapter already has the fix stored. To confirm it is active: dubfix verify\n");
    else say("\nThis adapter can be fixed. Nothing has been changed. To fix it: dubfix fix\n");
    return 0;
}
static int command_fix(const char *want)
{
    struct session s={0}; char where[PATH_BYTES+300];
    if (examine(&s,want)) return 1;
    if (s.fixed) {
        say("\nThis adapter already has the fix stored; nothing to write.\n"
            "Unplug it for five seconds, plug it back in, then run: dubfix verify\n");
        return 0;
    }
    if (unresolved_write(&s,where,sizeof(where))) {
        say("\nAn earlier write to this adapter did not finish cleanly, and the fix is not stored.\n"
            "Writing again could damage the adapter, so dubfix will not retry.\n");
        print_problems(where);
        say("See \"If the write fails\" in the README.\n");
        return 1;
    }
    say("Rehearsing the write without programming anything (the network link may drop briefly)... ");
    if (hardware_step(&s,"dry-run",NULL)) { say("failed.\n"); print_problems(s.last); return 1; }
    say("ok\n");
    if (stopped()) return 1;
    if (!confirmed(&s) || stop_requested) { say("Cancelled. Nothing was written.\n"); return 1; }
    say("Writing... ");
    int result=hardware_step(&s,"apply",s.token);
    if (result || read_outcome(s.last).stored!=1) {
        say("the write did not finish cleanly.\n");
        print_problems(s.last);
        say("Do not run fix again or try other tools yet. See \"If the write fails\" in the README.\n");
        return 1;
    }
    say("done. The adapter's memory was read back and is correct.\n\n"
        "Now unplug the adapter for five seconds, plug it back in, then run: dubfix verify\n");
    return 0;
}
static int command_verify(const char *want)
{
    struct session s={0}; char file[PATH_BYTES+32];
    if (select_adapter(&s,want)) return 1;
    snprintf(file,sizeof(file),"%s/backup.bin",s.backup);
    if (!exists(file)) {
        say("There is no backup for this adapter in %s.\n"
            "Run verify from the folder where you ran fix, or run \"dubfix check\" to see the adapter's state.\n",s.dir);
        return 1;
    }
    say("Reading the adapter... ");
    int result=hardware_step(&s,"verify",NULL);
    if (!result) {
        say("ok\n\nThe fix is stored and active: flow control is off.\n"
            "This only proves a cold start if you unplugged and replugged the adapter since the write.\n");
        return 0;
    }
    say("not verified.\n");
    if (read_outcome(s.last).stored==1)
        say("The fix is stored, but flow control is on right now. If you have not unplugged the adapter\n"
            "since the write, unplug it for five seconds, plug it back in, and run verify again.\n"
            "Otherwise something on this Mac is turning flow control back on.\n");
    print_problems(s.last);
    return 1;
}
static int usage(void)
{
    fputs("usage: dubfix check  [INTERFACE]   see whether the attached adapter can be fixed (changes nothing)\n"
          "       dubfix fix    [INTERFACE]   back up, rehearse, ask you to confirm, then write the fix\n"
          "       dubfix verify [INTERFACE]   after replugging, confirm the fix is stored and active\n"
          "\n"
          "INTERFACE (for example en7) is only needed when more than one adapter is attached.\n"
          "Backups and logs go in ./" DATA_DIR "/, one folder per adapter.\n"
          "The individual steps these commands run are available as \"dubfix step\".\n",stderr);
    return 2;
}
int main(int argc,char **argv)
{
    if (argc>=2 && argv[1] && !strcmp(argv[1],"step")) return dubfix_step(argc-1,argv+1);
    if (argc<2 || argc>3 || !argv[1] || (argc==3 && (!argv[2] || !*argv[2]))) return usage();
    const char *want=argc==3?argv[2]:NULL;
    /* Steps handle signals themselves; this process only stops between them. */
    struct sigaction stop={0},ignore={0};
    stop.sa_handler=on_stop; sigemptyset(&stop.sa_mask);
    ignore.sa_handler=SIG_IGN; sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGINT,&stop,NULL) || sigaction(SIGTERM,&stop,NULL) ||
        sigaction(SIGHUP,&stop,NULL) || sigaction(SIGPIPE,&ignore,NULL)) return 1;
    if (!strcmp(argv[1],"check")) return command_check(want);
    if (!strcmp(argv[1],"fix")) return command_fix(want);
    if (!strcmp(argv[1],"verify")) return command_verify(want);
    return usage();
}
