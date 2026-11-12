/*
 * dubfix: narrowly scoped DUB-E250 A1 / RTL8156B startup flow-control fix.
 * Fixed payload 20 e8 54 00 at physical eFuse 006c; no arbitrary writes.
 * The original, single-device prototype passed cold-start and 1Gbps tests.
 * This generalized source has programmed one further adapter; see docs/evidence.md.
 * OTP is irreversible. An apply command targets exactly one selected adapter.
 *
 * USB OUTs are closed to an audited list. No EEPROM/SPI, MCU/code RAM upload,
 * reset, reconfiguration, erase, compensation or second pulse is implemented.
 * Idle-sleep assertion and bounded finish/cleanup survive terminal loss;
 * explicit lid/power/disconnection actions can still interrupt the operation.
 */
#include "profile.h"
#include "transport_macos.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <mach/mach_error.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { OP_VERIFY=-2, OP_BACKUP=-1, OP_PREFLIGHT=0, OP_DRY=1, OP_PROGRAM=2,
       OTP_BYTES=DUBFIX_OTP_BYTES, OTP_OFFSET=DUBFIX_OFFSET };
enum { R_E84C, R_E81C, R_E85B, R_E0CA, R_CFD8, R_D848, N_REGS };
static const struct reg_def {
    uint16_t bank,address,mask; uint8_t shift,width,enable; const char *name;
} regs[N_REGS]={
    {0x100,0xe84c,0x0010,0,1,0x11,"PLA E84C"},
    {0x100,0xe81c,0x00c0,0,1,0x11,"PLA E81C"},
    {0x100,0xe858,0x00c4,3,1,0x88,"PLA E85B"},
    {0x100,0xe0c8,0x8000,2,2,0xcc,"PLA E0CA"},
    {0x000,0xcfd8,0x0001,0,2,0x33,"USB CFD8"},
    {0x000,0xd848,0x0008,0,2,0x33,"USB D848"}
};
static volatile sig_atomic_t interrupted;
struct transaction {
    struct adapter *a;
    struct adapter owned_adapter;
    struct dubfix_plan plan;
    uint8_t hardware_mac[6];
    unsigned ntb_size,driver_alloc;
    int identity_requires_backup;
    int mode,dir,log,exclusive,identity_valid,snapshot_valid;
    int baseline_valid,prepared,cleaning,finishing,dirty;
    int stage_attempted,pulse_attempted,program_idle_verified,otp_verified;
    int engine_unknown,log_failed,cleanup_verified,program_bit_observed;
    int stdout_failed,stdout_flags,stderr_flags,output_configured;
    int idle_assertion_created;
    IOPMAssertionID idle_assertion;
    unsigned read_commands,margin_commands,last_read_bytes;
    uint16_t saved[N_REGS],selector,b400,b430;
    uint8_t cfg_dirty[N_REGS];
    int selector_valid,selector_dirty,b400_valid,b430_valid,b400_dirty,b430_dirty;
    double deadline;
};

static double now_seconds(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    return (double)t.tv_sec+(double)t.tv_nsec/1e9;
}
static void on_signal(int sig) { (void)sig; interrupted=1; }
/* Pure process setup, factored for offline broken-pipe fault tests. */
static int install_signal_handlers(void)
{
    struct sigaction sa={0},ignore={0};
    ignore.sa_handler=SIG_IGN; sigemptyset(&ignore.sa_mask);
    sa.sa_handler=on_signal; sigemptyset(&sa.sa_mask);
    return sigaction(SIGPIPE,&ignore,NULL) || sigaction(SIGINT,&sa,NULL) ||
           sigaction(SIGTERM,&sa,NULL) || sigaction(SIGHUP,&sa,NULL) ? -1:0;
}
/* Terminal output is a best-effort mirror, never a blocking dependency of a pulse
 * or cleanup. Keep inherited request() diagnostics on nonblocking stderr too.
 * Unbuffered stdio prevents an atexit flush after restoring original FD flags.
 */
static int configure_output(struct transaction *t)
{
    if (setvbuf(stdout,NULL,_IONBF,0) || setvbuf(stderr,NULL,_IONBF,0)) return -1;
    t->stdout_flags=fcntl(STDOUT_FILENO,F_GETFL);
    t->stderr_flags=fcntl(STDERR_FILENO,F_GETFL);
    if (t->stdout_flags<0 || t->stderr_flags<0) return -1;
    if (fcntl(STDOUT_FILENO,F_SETFL,t->stdout_flags|O_NONBLOCK)) return -1;
    t->output_configured|=1;
    if (fcntl(STDERR_FILENO,F_SETFL,t->stderr_flags|O_NONBLOCK)) return -1;
    t->output_configured|=2;
    return 0;
}
static int restore_output(struct transaction *t)
{
    int failed=0;
    if ((t->output_configured&1) && fcntl(STDOUT_FILENO,F_SETFL,t->stdout_flags)) failed=1;
    if ((t->output_configured&2) && fcntl(STDERR_FILENO,F_SETFL,t->stderr_flags)) failed=1;
    return failed?-1:0;
}
static int alive(struct transaction *t)
{
    double n=now_seconds();
    return (n<0 || n>=t->deadline || (!t->cleaning && !t->finishing && interrupted)) ? -1:0;
}
static void journal(struct transaction *t,const char *format,...)
{
    char line[2048]; va_list ap;
    va_start(ap,format); int n=vsnprintf(line,sizeof(line),format,ap); va_end(ap);
    if (n<0 || (size_t)n>=sizeof(line)) { t->log_failed=1; return; }
    /* Durable local journal first. A lost/blocked terminal mirror is separate. */
    if (t->log>=0) {
        size_t used=0;
        while (used<(size_t)n) {
            ssize_t r=write(t->log,line+used,(size_t)n-used);
            if (r<0 && errno==EINTR) continue;
            if (r<=0) { t->log_failed=1; break; }
            used+=(size_t)r;
        }
    }
    if (!t->stdout_failed) {
        ssize_t mirrored=write(STDOUT_FILENO,line,(size_t)n);
        if (mirrored!=n) t->stdout_failed=1;
    }
}
static void sha(const void *data,size_t len,uint8_t result[32])
{ dubfix_sha256(data,len,result); }
static void print_sha(struct transaction *t,const char *label,const void *data,size_t len)
{
    uint8_t hash[32]; char hex[65]; sha(data,len,hash);
    for (int i=0;i<32;i++) snprintf(hex+i*2,3,"%02x",hash[i]);
    journal(t,"%s SHA256=%s\n",label,hex);
}
static int save_file(struct transaction *t,const char *name,const void *data,size_t len)
{
    int fd=openat(t->dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (fd<0) { perror(name); return -1; }
    const uint8_t *p=data; size_t used=0; int failed=0;
    while (used<len) {
        ssize_t n=write(fd,p+used,len-used);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { failed=1; break; } used+=(size_t)n;
    }
    if (fsync(fd)) failed=1;
    if (close(fd)) failed=1;
    return failed?-1:0;
}
/* Accept a private backup file, or a backup directory containing backup.bin. */
static int load_original(const char *path,uint8_t data[OTP_BYTES])
{
    int fd=open(path,O_RDONLY|O_NOFOLLOW); struct stat st; int failed=0;
    if (fd<0) { perror(path); return -1; }
    if (fstat(fd,&st)) { close(fd); return -1; }
    if (S_ISDIR(st.st_mode)) {
        int inner=openat(fd,"backup.bin",O_RDONLY|O_NOFOLLOW);
        if (close(fd) || inner<0) { if (inner>=0) close(inner); return -1; }
        fd=inner;
        if (fstat(fd,&st)) { close(fd); return -1; }
    }
    if (!S_ISREG(st.st_mode) || st.st_uid!=getuid() ||
        (st.st_mode&0022) || st.st_size!=OTP_BYTES) failed=1;
    size_t used=0;
    while (!failed && used<OTP_BYTES) {
        ssize_t n=read(fd,data+used,OTP_BYTES-used);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { failed=1; break; } used+=(size_t)n;
    }
    if (close(fd)) failed=1;
    return failed?-1:0;
}
static int read32(struct transaction *t,uint16_t bank,uint16_t address,uint32_t *value)
{
    uint32_t raw=0;
    if (!value || (bank!=0 && bank!=0x100) || (address&3) || alive(t)) return -1;
    if (request(t->a,0xc0,5,address,bank,&raw,4)) return -1;
    *value=OSReadLittleInt32(&raw,0);
    if (bank==0x100 && address==0xdd04 && (*value&0x4000)) t->program_bit_observed=1;
    return 0;
}

/* Sole OUT site. Normal/margin reads are not OTP-program commands.
 * Irreversible stage+trigger are hardwired to ONE value/index and mode gated.
 */
static int out4(struct transaction *t,uint16_t bank,uint16_t address,
                uint16_t enable,uint32_t value)
{
    int allowed=0;
    if (!t->identity_valid || (bank!=0 && bank!=0x100) || (address&3) || alive(t)) return -1;
    for (int i=0;i<N_REGS;i++)
        if (bank==regs[i].bank && address==regs[i].address && enable==regs[i].enable &&
            t->snapshot_valid && (i==R_E85B || t->mode>=OP_DRY)) allowed=1;
    if (bank==0x100 && address==0xe86c && enable==0x33 && t->selector_valid &&
        ((value&0xffff)==0xa000 || (value&0xffff)==t->selector)) allowed=1;
    if (bank==0x100 && address==0xb430 && enable==0x33 && t->mode>=OP_DRY && t->b430_valid) allowed=1;
    if (bank==0x100 && address==0xb400 && enable==0x33 && t->mode>=OP_DRY && t->b400_valid &&
        ((value&0xffff)==0x1800 || (value&0xffff)==t->b400)) allowed=1;
    if (bank==0x100 && address==0xdd04 && enable==0x33 && t->snapshot_valid) {
        if ((value&0xfffffe00u)==0x8000u) { allowed=1; t->read_commands++; }
        if (value==0x881b && t->mode>=OP_DRY && t->prepared) { allowed=1; t->margin_commands++; }
        if (value==0x401b && t->mode==OP_PROGRAM && t->prepared && t->baseline_valid &&
            t->plan.state==DUBFIX_FIXABLE && t->stage_attempted && !t->pulse_attempted && !interrupted && !t->log_failed && !t->stdout_failed) {
            journal(t,"IRREVERSIBLE PROGRAM trigger about to be attempted ONCE: DD04=401b.\n");
            if (t->log_failed || fsync(t->log) || alive(t) || interrupted || t->stdout_failed) return -1;
            allowed=1; t->pulse_attempted=1; t->finishing=1;
        }
    }
    if (bank==0x100 && address==0xdd00 && enable==0xff && value==0x0054e820 &&
        t->mode==OP_PROGRAM && t->plan.state==DUBFIX_FIXABLE && t->prepared && t->baseline_valid && !t->stage_attempted &&
        !t->pulse_attempted && !interrupted && !t->log_failed && !t->stdout_failed) {
        allowed=1; t->stage_attempted=1;
    }
    if (!allowed) {
        journal(t,"REFUSED OUT bank=%04x address=%04x enable=%04x value=%08x\n",bank,address,enable,value);
        return -1;
    }
    uint32_t raw=0; OSWriteLittleInt32(&raw,0,value); t->dirty=1;
    return request(t->a,0x40,5,address,(uint16_t)(bank|enable),&raw,4);
}
static uint16_t reg_value(int i,uint32_t raw)
{
    unsigned shift=regs[i].shift*8;
    return (uint16_t)((raw>>shift)&(regs[i].width==1?0xffu:0xffffu));
}
static int update_reg(struct transaction *t,int i,uint16_t wanted)
{
    uint32_t before,after;
    if (i<0 || i>=N_REGS || read32(t,regs[i].bank,regs[i].address,&before)) return -1;
    uint16_t old=reg_value(i,before),mask=regs[i].mask;
    uint16_t merged=(uint16_t)((old&~mask)|(wanted&mask));
    unsigned shift=regs[i].shift*8;
    uint32_t field=(regs[i].width==1?0xffu:0xffffu)<<shift;
    uint32_t raw=(before&~field)|((uint32_t)merged<<shift);
    t->cfg_dirty[i]=1;
    int r=out4(t,regs[i].bank,regs[i].address,regs[i].enable,raw);
    int rr=read32(t,regs[i].bank,regs[i].address,&after);
    journal(t,"%s ownedmask=%04x before=%04x wanted=%04x after=%04x OUT=%d IN=%d\n",
            regs[i].name,mask,old,merged,rr?0xffff:reg_value(i,after),r,rr);
    if (r || rr || ((reg_value(i,after)^merged)&mask)) return -1;
    return 0;
}
static int selector_set(struct transaction *t,uint16_t value)
{
    uint32_t raw,check;
    if (!t->selector_valid || read32(t,0x100,0xe86c,&raw)) return -1;
    raw=(raw&0xffff0000u)|value; t->selector_dirty=1;
    int r=out4(t,0x100,0xe86c,0x33,raw);
    if (read32(t,0x100,0xe86c,&check) || (check&0xffff)!=value) return -1;
    return r;
}
static int selector_restore(struct transaction *t)
{
    int was=t->cleaning; double deadline=t->deadline;
    t->cleaning=1; t->deadline=now_seconds()+5;
    int r=selector_set(t,t->selector);
    if (!r) t->selector_dirty=0;
    t->cleaning=was; t->deadline=deadline;
    return r;
}
static int phy_snapshot(struct transaction *t)
{
    uint32_t raw; int failed=0;
    if (selector_set(t,0xa000)) failed=1;
    if (!failed && read32(t,0x100,0xb400,&raw)) failed=1;
    if (!failed) { t->b400=(uint16_t)raw; t->b400_valid=1; }
    if (!failed && read32(t,0x100,0xb430,&raw)) failed=1;
    if (!failed) { t->b430=(uint16_t)raw; t->b430_valid=1; }
    if (selector_restore(t)) failed=1;
    if (!failed && (t->b400&0x8200)) {
        journal(t,"Refusing PHY BMCR reset/restart busy baseline=%04x.\n",t->b400); failed=1;
    }
    return failed?-1:0;
}
static int phy_update(struct transaction *t,int bmcr,uint16_t wanted)
{
    uint16_t address=bmcr?0xb400:0xb430,mask=bmcr?0xffff:0x0004;
    uint32_t raw=0,check=0; int failed=0;
    if (selector_set(t,0xa000)) failed=1;
    if (!failed && read32(t,0x100,address,&raw)) failed=1;
    if (!failed && bmcr && ((uint16_t)raw&0x8200)) {
        journal(t,"Refusing PHY BMCR update while reset/restart busy=%04x.\n",(uint16_t)raw); failed=1;
    }
    uint16_t old=(uint16_t)raw,merged=(uint16_t)((old&~mask)|(wanted&mask));
    if (!failed) {
        if (bmcr) t->b400_dirty=1; else t->b430_dirty=1;
        int r=out4(t,0x100,address,0x33,(raw&0xffff0000u)|merged);
        int rr=read32(t,0x100,address,&check);
        journal(t,"GPHY A000:%04x mask=%04x old=%04x wanted=%04x after=%04x OUT=%d IN=%d\n",
                address,mask,old,merged,(uint16_t)check,r,rr);
        if (r || rr || (((uint16_t)check^merged)&mask)) failed=1;
    }
    if (selector_restore(t)) failed=1;
    return failed?-1:0;
}
static int snapshot_controls(struct transaction *t)
{
    uint32_t raw;
    for (int i=0;i<N_REGS;i++) {
        if (read32(t,regs[i].bank,regs[i].address,&raw)) return -1;
        t->saved[i]=reg_value(i,raw);
    }
    if ((t->saved[R_E85B]&0xc4) || read32(t,0x100,0xdd04,&raw) || (raw&0xc000)) return -1;
    if (read32(t,0x100,0xe86c,&raw)) return -1;
    t->selector=(uint16_t)raw; t->selector_valid=1;
    t->snapshot_valid=1; /* All normal controls and the selector are captured. */
    if (phy_snapshot(t)) return -1;
    uint8_t serialized[(N_REGS+3)*2];
    for (int i=0;i<N_REGS;i++) OSWriteLittleInt16(serialized,i*2,t->saved[i]);
    OSWriteLittleInt16(serialized,N_REGS*2,t->selector);
    OSWriteLittleInt16(serialized,(N_REGS+1)*2,t->b400);
    OSWriteLittleInt16(serialized,(N_REGS+2)*2,t->b430);
    for (int i=0;i<N_REGS;i++) journal(t,"Saved %s=%04x ownedmask=%04x\n",regs[i].name,t->saved[i],regs[i].mask);
    journal(t,"Saved E86C=%04x GPHY A000:B400=%04x B430=%04x\n",t->selector,t->b400,t->b430);
    return save_file(t,"controls-before.bin",serialized,sizeof(serialized));
}
static int engine_idle(struct transaction *t,uint32_t *last)
{
    uint32_t raw;
    if (read32(t,0x100,0xdd04,&raw)) return -1;
    if (last) *last=raw;
    return raw&0xc000?-1:0;
}
static int wait_engine(struct transaction *t,uint16_t busy,double seconds)
{
    double end=now_seconds()+seconds; unsigned count=0; uint32_t raw=0;
    do {
        if (read32(t,0x100,0xdd04,&raw)) return -1;
        if (busy==0x8000 && (raw&0x4000)) return -1;
        if (!(raw&busy)) return (raw&0xc000)?-1:0;
        if (++count>=10000 || now_seconds()>=end || alive(t)) break;
        usleep(100);
    } while (1);
    journal(t,"Engine wait failed: busy=%04x lastDD04=%08x polls=%u\n",busy,raw,count);
    return -1;
}
static int access_is_enabled(struct transaction *t)
{
    uint32_t raw;
    return read32(t,0x100,0xe858,&raw) ||
        reg_value(R_E85B,raw)!=(uint16_t)(t->saved[R_E85B]|0xc4)?-1:0;
}
static int read_word(struct transaction *t,unsigned offset,int margin,uint32_t *value)
{
    if (offset>=OTP_BYTES || (offset&3) || (margin && offset!=OTP_OFFSET) ||
        engine_idle(t,NULL) || access_is_enabled(t)) return -1;
    uint16_t command=(uint16_t)((margin?0x8800:0x8000)|(offset>>2));
    if (out4(t,0x100,0xdd04,0x33,command) || wait_engine(t,0x8000,1.0) ||
        read32(t,0x100,0xdd00,value)) return -1;
    return 0;
}
static int read_all(struct transaction *t,uint8_t data[OTP_BYTES])
{
    t->last_read_bytes=0;
    for (unsigned offset=0;offset<OTP_BYTES;offset+=4) {
        uint32_t value;
        if (read_word(t,offset,0,&value)) {
            journal(t,"OTP READ failed at offset=%04x; observed prefix=%u bytes. Remaining bytes were NOT observed physical data.\n",offset,t->last_read_bytes);
            return -1;
        }
        OSWriteLittleInt32(data,offset,value); t->last_read_bytes=offset+4;
    }
    return 0;
}
static int prepare(struct transaction *t)
{
    if (t->mode<OP_DRY || !t->baseline_valid || !t->b400_valid || !t->b430_valid) return -1;
    if (update_reg(t,R_E84C,(uint16_t)(t->saved[R_E84C]|0x10)) ||
        update_reg(t,R_CFD8,(uint16_t)(t->saved[R_CFD8]&~1u)) ||
        phy_update(t,0,(uint16_t)(t->b430&~4u)) ||
        update_reg(t,R_D848,(uint16_t)(t->saved[R_D848]&~8u)) ||
        update_reg(t,R_E0CA,(uint16_t)(t->saved[R_E0CA]&~0x8000u)) ||
        phy_update(t,1,0x1800) ||
        update_reg(t,R_E81C,(uint16_t)(t->saved[R_E81C]|0xc0)) ||
        update_reg(t,R_E85B,(uint16_t)(t->saved[R_E85B]|0xc4))) return -1;
    t->prepared=1;
    journal(t,"Vendor B PG preparation verified. No OTP program command has been sent.\n");
    return 0;
}
static int verify_controls(struct transaction *t)
{
    uint32_t raw; int failed=0;
    for (int i=0;i<N_REGS;i++)
        if (read32(t,regs[i].bank,regs[i].address,&raw) ||
            ((reg_value(i,raw)^t->saved[i])&regs[i].mask)) failed=1;
    if (read32(t,0x100,0xe86c,&raw) || (uint16_t)raw!=t->selector) failed=1;
    if (!t->b400_valid || !t->b430_valid) return failed?-1:0;
    if (selector_set(t,0xa000)) failed=1;
    if (read32(t,0x100,0xb400,&raw) || (uint16_t)raw!=t->b400) failed=1;
    if (read32(t,0x100,0xb430,&raw) || (((uint16_t)raw^t->b430)&4)) failed=1;
    if (selector_restore(t)) failed=1;
    return failed?-1:0;
}
static int cleanup(struct transaction *t)
{
    int failed=0; uint32_t status=0;
    t->cleaning=1; t->deadline=now_seconds()+30;
    /* Never disable access/clock/power under an unknown or still-busy pulse.
     * This conservative policy differs from vendor's unconditional access-clear.
     */
    int status_valid=!read32(t,0x100,0xdd04,&status);
    int idle=status_valid && !(status&0xc000);
    if (!idle && !t->pulse_attempted && !t->program_bit_observed) {
        /* No irreversible command was ever attempted. Wait briefly using
         * pure status INs, then perform the audited reader's best-effort
         * access restoration even if its read command has not completed.
         * This exception NEVER applies to an attempted/observed program.
         */
        double end=now_seconds()+2.0;
        while (status_valid && (status&0x8000) && !t->program_bit_observed &&
               now_seconds()<end && !alive(t)) {
            usleep(10000);
            status_valid=!read32(t,0x100,0xdd04,&status);
        }
        idle=status_valid && !(status&0xc000);
        if (!idle && !t->program_bit_observed)
            journal(t,"No PROGRAM was attempted/observed. READ-only engine state is not idle/available; attempting bounded access/PHY/control restoration (no command replay).\n");
    }
    if (!idle && (t->pulse_attempted || t->program_bit_observed)) {
        t->engine_unknown=1;
        journal(t,"ERROR: program-capable engine not verified idle (statusValid=%d lastDD04=%08x). Volatile PG state is LEFT AS-IS; no access/power/PHY cleanup, reset or retry is attempted. Human review required.\n",status_valid,status);
        return -1;
    }
    if (t->cfg_dirty[R_E85B] && update_reg(t,R_E85B,t->saved[R_E85B])) failed=1;
    if (t->cfg_dirty[R_E81C] && update_reg(t,R_E81C,t->saved[R_E81C])) failed=1;
    if (t->b400_dirty && phy_update(t,1,t->b400)) failed=1;
    if (t->cfg_dirty[R_E0CA] && update_reg(t,R_E0CA,t->saved[R_E0CA])) failed=1;
    if (t->cfg_dirty[R_D848] && update_reg(t,R_D848,t->saved[R_D848])) failed=1;
    if (t->b430_dirty && phy_update(t,0,t->b430)) failed=1;
    if (t->cfg_dirty[R_CFD8] && update_reg(t,R_CFD8,t->saved[R_CFD8])) failed=1;
    if (t->cfg_dirty[R_E84C] && update_reg(t,R_E84C,t->saved[R_E84C])) failed=1;
    if (t->selector_valid && selector_restore(t)) failed=1;
    if (t->snapshot_valid && verify_controls(t)) failed=1;
    if (engine_idle(t,&status)) {
        journal(t,"ERROR: final controller idle state is not verified after restoration, DD04=%08x.\n",status); failed=1;
    }
    t->cleanup_verified=!failed;
    journal(t,"Volatile owned-control restoration %s. Network link/throughput must be checked externally.\n",failed?"NOT VERIFIED":"verified");
    return failed?-1:0;
}
/* The base identity permits a previously fixed adapter to be read. Startup
 * defaults needed by the programmer are checked only after NVM classification. */
static int identity(struct transaction *t,const char *iface)
{
    if (!iface || !*iface || strlen(iface)>=IFNAMSIZ || t->dir<0 || t->log<0) return -1;
    struct adapter list[MAX_ADAPTERS]; int n=find_adapters(list); unsigned config=0;
    if (n<0) return -1;
    for (int i=0;i<n;i++) {
        if (!t->a && !strcmp(list[i].name,iface)) {
            t->owned_adapter=list[i]; t->a=&t->owned_adapter;
        } else close_device(&list[i]);
    }
    if (!t->a) { journal(t,"No Apple NCM adapter matches interface %s.\n",iface); return -1; }
    struct adapter *a=t->a;
    uint32_t raw[2],marker,ue,pe;
    if (a->vid!=0x2001 || a->pid!=0xb301 || a->release!=0x3100 ||
        number_property(a->usb,CFSTR(kUSBHostDevicePropertyCurrentConfiguration),&config) || config!=2 ||
        open_device(a) || identify_chip(a) || a->version!=0x7410 ||
        read32(t,0x100,0xc000,&raw[0]) || read32(t,0x100,0xc004,&raw[1])) {
        journal(t,"Refused: requires USB2001:b301 release3100, chip7410, configuration2.\n"); return -1;
    }
    uint8_t bytes[8],validated[6]; char mac[18];
    OSWriteLittleInt32(bytes,0,raw[0]); OSWriteLittleInt32(bytes,4,raw[1]);
    dubfix_mac_string(bytes,mac);
    if (dubfix_parse_mac(mac,validated) ||
        (t->identity_requires_backup && memcmp(validated,t->plan.mac,6))) {
        journal(t,"Refused: hardware MAC is invalid or does not match the backup factory MAC.\n"); return -1;
    }
    memcpy(t->hardware_mac,validated,6);
    if (read32(t,0,0xcfd4,&marker) || (marker&0xffff0000u) ||
        read32(t,0,0xfc48,&ue) || (ue&0xffff) ||
        read32(t,0x100,0xfc38,&pe) || (pe&0xffff) ||
        find_ncm(a) || get_size(a,&t->ntb_size) ||
        t->ntb_size<2048 || t->ntb_size>65536 ||
        a->read_size<2048 || a->read_size>65536) {
        journal(t,"Refused: active MCU patches, unavailable NCM descriptors, or invalid NTB/allocation.\n"); return -1;
    }
    t->driver_alloc=a->read_size;
    journal(t,"Target %s hardwareMAC=%s USB2001:b301/3100/chip7410/NCM2; patchmarkers/enables0; NTB=%u driverAllocation=%u (observed only, never changed).\n",
            iface,mac,t->ntb_size,t->driver_alloc);
    t->identity_valid=1;
    IOReturn r=(*a->dev)->USBDeviceOpen(a->dev);
    journal(t,"Ordinary exclusive USBDeviceOpen=%08x (%s); no seizure fallback.\n",(unsigned)r,mach_error_string(r));
    if (r!=kIOReturnSuccess) return -1;
    t->exclusive=1; return 0;
}
static int fresh_state(struct transaction *t)
{
    uint32_t cpcr,cfee,ncm;
    if (read32(t,0x100,0xe854,&cpcr) || (cpcr&0xff)!=1 ||
        read32(t,0,0xcfec,&cfee) || ((cfee>>16)&0xff)!=4 ||
        read32(t,0,0xd330,&ncm) || ((ncm>>16)&0xff)!=0) {
        journal(t,"Refused fresh-device preparation: requires CPCRlow01 CFEE04 NCMoption0. Reconnect cleanly and inspect any host-side helper; this tool never changes NTB or host services.\n");
        return -1;
    }
    journal(t,"Fresh-device mutating-state guard: CPCRlow01 CFEE04 NCMoption0 verified after physical NVM classification.\n");
    return 0;
}
static int pulse(struct transaction *t,const uint8_t expected[OTP_BYTES])
{
    uint32_t margin=0,normal=0; uint8_t after[OTP_BYTES]={0};
    if (t->mode!=OP_PROGRAM || t->plan.state!=DUBFIX_FIXABLE || !t->prepared || !t->baseline_valid ||
        interrupted || t->log_failed || t->stdout_failed || engine_idle(t,NULL) || access_is_enabled(t)) return -1;
    journal(t,"Next operation stages0054e820 then irreversibly programs ONLY OTP DWORD006c with one401b command.\n");
    if (fsync(t->log) || fsync(t->dir) || t->stdout_failed || alive(t)) return -1;
    if (out4(t,0x100,0xdd00,0xff,0x0054e820)) return -1;
    /* Follow the audited vendor stage->trigger sequence without an extra
     * DD00 IN: pre-trigger read-latch semantics have not been established.
     * The USB transport already checks control success and completed length.
     */
    /* Set finishing before poll so a caught signal cannot abandon a live pulse. */
    int sent=out4(t,0x100,0xdd04,0x33,0x401b);
    t->deadline=now_seconds()+45;
    if (!t->pulse_attempted) return -1;
    if (wait_engine(t,0x4000,10.0)) {
        t->engine_unknown=1;
        journal(t,"ERROR: program completion is unknown. No second pulse/read command/reset will be sent.\n");
        return -1;
    }
    t->program_idle_verified=1;
    if (sent) {
        journal(t,"ERROR: program OUT reported an error, although idle is now observed. OTP outcome remains unknown; no read/program retry.\n");
        return -1;
    }
    if (read_word(t,OTP_OFFSET,1,&margin) || margin!=0x0054e820 ||
        read_word(t,OTP_OFFSET,0,&normal) || normal!=0x0054e820) {
        journal(t,"ERROR: candidate verification failed margin=%08x normal=%08x. No program retry.\n",margin,normal);
        return -1;
    }
    journal(t,"Program-margin=%08x normal=%08x verified.\n",margin,normal);
    if (read_all(t,after)) {
        journal(t,"ERROR: post-program OTP read was partial (%u of2048 bytes); the unobserved tail cannot be assessed as physical data.\n",t->last_read_bytes);
        (void)save_file(t,"post-program-partial-unverified.bin",after,t->last_read_bytes);
        return -1;
    }
    if (memcmp(after,expected,OTP_BYTES)) {
        journal(t,"ERROR: a COMPLETE2048-byte post-program OTP read differs from the exact four-byte candidate image.\n");
        (void)save_file(t,"post-program-full-unverified.bin",after,sizeof(after));
        print_sha(t,"Complete but unexpected post-program OTP",after,sizeof(after)); return -1;
    }
    if (save_file(t,"post-program-verified.bin",after,sizeof(after))) return -1;
    print_sha(t,"Post-program OTP",after,sizeof(after)); t->otp_verified=1;
    journal(t,"Exactly20e85400 at006c changed; all other2044 physical bytes match backup. Cold-start effectiveness is NOT established.\n");
    return 0;
}
#define TOKEN_BYTES 160
static void make_token(const struct dubfix_plan *p,char out[TOKEN_BYTES])
{
    char hash[65]; dubfix_hash_string(p->before_sha,hash);
    snprintf(out,TOKEN_BYTES,"PROGRAM-20E85400-AT-006C-MAC-%02X%02X%02X%02X%02X%02X-SHA256-%s",
             p->mac[0],p->mac[1],p->mac[2],p->mac[3],p->mac[4],p->mac[5],hash);
}
static const char *state_name(enum dubfix_profile_state state)
{
    return state==DUBFIX_FIXABLE?"fixable":state==DUBFIX_ALREADY_FIXED?"already-fixed":"unsupported";
}
static int report_plan(struct transaction *t,const uint8_t before[OTP_BYTES],const char *reason,int save)
{
    char text[2048],mac[18]="unavailable",hardware[18],before_hash[65],after_hash[65],token[TOKEN_BYTES];
    uint8_t valid_hardware[6];
    uint8_t hash[32]; sha(before,OTP_BYTES,hash); dubfix_hash_string(hash,before_hash);
    const struct dubfix_plan *p=&t->plan;
    if (p->state!=DUBFIX_UNSUPPORTED) dubfix_mac_string(p->mac,mac);
    dubfix_mac_string(t->hardware_mac,hardware);
    if (dubfix_parse_mac(hardware,valid_hardware)) strcpy(hardware,"unavailable");
    dubfix_hash_string(p->after_sha,after_hash); make_token(p,token);
    int n=snprintf(text,sizeof(text),
        "dubfix profile-v1\nClassification: %s\nReason: %s\nFactory MAC: %s\nHardware MAC: %s\n"
        "Physical backup bytes: 2048\nBefore SHA256: %s\n",
        state_name(p->state),reason,mac,hardware,before_hash);
    if (n<0 || (size_t)n>=sizeof(text)) return -1;
    if (p->state!=DUBFIX_UNSUPPORTED) {
        int extra=snprintf(text+(size_t)n,sizeof(text)-(size_t)n,
            "Expected SHA256: %s\nFixed record: 006c: 20 e8 54 00\n"
            "Proposed change: %s\nConfirmation token: %s\n"
            "Apply programs one selected adapter only. eFuse is irreversible.\n"
            "A stored record and a current runtime setting do not prove a cold start.\n",
            after_hash,p->state==DUBFIX_FIXABLE?"006c..006f: ff ff ff ff -> 20 e8 54 00; all other 2044 bytes preserved":"none; fixed record already present",token);
        if (extra<0 || (size_t)extra>=sizeof(text)-(size_t)n) return -1;
        n+=extra;
    } else {
        int extra=snprintf(text+(size_t)n,sizeof(text)-(size_t)n,
                          "No programming plan is available. Preserve this private dump for inspection.\n");
        if (extra<0 || (size_t)extra>=sizeof(text)-(size_t)n) return -1;
        n+=extra;
    }
    journal(t,"%s",text);
    return save?save_file(t,"plan.txt",text,(size_t)n):0;
}
static int create_report(struct transaction *t,const char *path)
{
    if (mkdir(path,0700)) { perror("create NEW report directory"); return -1; }
    t->dir=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW); struct stat st;
    if (t->dir<0 || fstat(t->dir,&st) || st.st_uid!=getuid() || (st.st_mode&0077)) return -1;
    t->log=openat(t->dir,"transaction.log",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    return t->log<0?-1:0;
}
/* Pure NVM reads require only temporary eFuse access and selector restoration;
 * no PG clock/power-down preparation is used here or in verify. */
static int double_read(struct transaction *t,uint8_t first[OTP_BYTES],uint8_t second[OTP_BYTES])
{
    if (update_reg(t,R_E85B,(uint16_t)(t->saved[R_E85B]|0xc4))) return -1;
    if (read_all(t,first)) {
        (void)save_file(t,"first-read-partial-unverified.bin",first,t->last_read_bytes); return -1;
    }
    if (save_file(t,"actual-before.bin",first,OTP_BYTES)) return -1;
    if (read_all(t,second)) {
        (void)save_file(t,"repeat-read-partial-unverified.bin",second,t->last_read_bytes); return -1;
    }
    if (save_file(t,"actual-before-repeat.bin",second,OTP_BYTES) ||
        update_reg(t,R_E85B,t->saved[R_E85B])) return -1;
    if (memcmp(first,second,OTP_BYTES)) {
        journal(t,"Refused: two complete physical NVM reads disagree.\n"); return -1;
    }
    journal(t,"Two complete 2048-byte physical NVM reads agree.\n");
    return 0;
}
static int runtime_report(struct transaction *t)
{
    uint32_t cpcr; unsigned size;
    if (read32(t,0x100,0xe854,&cpcr) || get_size(t->a,&size) || size<2048 || size>65536) return -1;
    journal(t,"Runtime CPCRlow=%02x FLOW_CTRL_EN=%u; NTB=%u driverAllocation=%u; no NTB SET sent.\n",
            (unsigned)(cpcr&0xff),(unsigned)(cpcr&1),size,t->driver_alloc);
    journal(t,"Cold-start validation requires an operator USB power cycle between observations; this command cannot establish one.\n");
    return (cpcr&0xff)==0?0:-1;
}
static int list_devices(struct transaction *t)
{
    struct adapter list[MAX_ADAPTERS]; int n=find_adapters(list),result=0,found=0;
    if (n<0) return -1;
    for (int i=0;i<n;i++) {
        struct adapter *a=&list[i];
        if (a->vid==0x2001 && a->pid==0xb301) {
            unsigned config=0,size=0; int ok; char mac[18]="unreadable";
            uint32_t raw[2]; uint8_t bytes[8],validated[6];
            struct transaction reader=*t; reader.a=a;
            found++;
            ok=!open_device(a) && !identify_chip(a) && !find_ncm(a) && !get_size(a,&size) &&
               !number_property(a->usb,CFSTR(kUSBHostDevicePropertyCurrentConfiguration),&config);
            if (ok) {
                ok=!read32(&reader,0x100,0xc000,&raw[0]) && !read32(&reader,0x100,0xc004,&raw[1]);
                if (ok) {
                    OSWriteLittleInt32(bytes,0,raw[0]); OSWriteLittleInt32(bytes,4,raw[1]);
                    dubfix_mac_string(bytes,mac);
                    if (dubfix_parse_mac(mac,validated)) { strcpy(mac,"invalid"); ok=0; }
                }
            }
            journal(t,"%s hardwareMAC=%s USB=%04x:%04x release=%04x chip=%04x configuration=%u NTB=%u driverAllocation=%u profileHardware=%s\n",
                    a->name,mac,a->vid,a->pid,a->release,a->version,config,size,a->read_size,
                    ok && a->release==0x3100 && a->version==0x7410 && config==2?"candidate (backup required)":"unsupported/unreadable");
            if (!ok) result=-1;
        }
        close_device(a);
    }
    if (!found) journal(t,"No D-Link 2001:b301 adapter attached to the Apple NCM driver.\n");
    return result;
}
static int otp_usage(void)
{
    fputs("usage: dubfix step list\n"
          "       dubfix step backup IFACE NEWDIR\n"
          "       dubfix step plan BACKUP\n"
          "       dubfix step preflight IFACE BACKUP NEWREPORTDIR\n"
          "       dubfix step dry-run IFACE BACKUP NEWREPORTDIR\n"
          "       dubfix step apply IFACE BACKUP NEWREPORTDIR CONFIRM_TOKEN\n"
          "       dubfix step verify IFACE BACKUP NEWREPORTDIR\n"
          "These are the steps that check, fix and verify run for you.\n"
          "BACKUP is backup.bin or its directory. Every output directory must be new.\n"
          "plan is offline. list sends USB IN requests only. Other read modes use temporary NVM access controls.\n"
          "Only apply can program eFuse: one fixed four-byte record, one selected device, one attempt.\n"
          "eFuse cannot be erased; apply requires the exact per-device token from plan.\n",stderr);
    return 2;
}
/* One step per process. argv[0] is ignored; src/cli.c calls this for
 * "dubfix step ..." and runs the steps in order for check, fix and verify. */
int dubfix_step(int argc,char **argv);
int dubfix_step(int argc,char **argv)
{
    struct transaction t={.dir=-1,.log=-1};
    uint8_t reference[OTP_BYTES]={0},first[OTP_BYTES]={0},second[OTP_BYTES]={0};
    char reason[256]="",token[TOKEN_BYTES];
    int result=1,is_list=0,is_plan=0;
    const char *iface=NULL,*backup=NULL,*report=NULL;
    t.plan.state=DUBFIX_UNSUPPORTED;
    interrupted=0;
    if (argc<2 || !argv) return otp_usage();
    for (int i=0;i<argc;i++) if (!argv[i]) return otp_usage();
    if (!strcmp(argv[1],"list")) { if (argc!=2) return otp_usage(); is_list=1; }
    else if (!strcmp(argv[1],"plan")) { if (argc!=3) return otp_usage(); is_plan=1; backup=argv[2]; }
    else if (!strcmp(argv[1],"backup")) {
        if (argc!=4) return otp_usage();
        t.mode=OP_BACKUP; iface=argv[2]; report=argv[3];
    } else {
        if (!strcmp(argv[1],"preflight")) t.mode=OP_PREFLIGHT;
        else if (!strcmp(argv[1],"dry-run")) t.mode=OP_DRY;
        else if (!strcmp(argv[1],"apply")) t.mode=OP_PROGRAM;
        else if (!strcmp(argv[1],"verify")) t.mode=OP_VERIFY;
        else return otp_usage();
        if (argc!=(t.mode==OP_PROGRAM?6:5)) return otp_usage();
        iface=argv[2]; backup=argv[3]; report=argv[4]; t.identity_requires_backup=1;
    }
    if (iface && (!*iface || strlen(iface)>=IFNAMSIZ)) return otp_usage();
    if (backup) {
        if (load_original(backup,reference)) {
            fputs("Refused backup: requires an owned, regular, exactly 2048-byte, non-writable-by-others file with no symlink.\n",stderr); return 1;
        }
        if (dubfix_make_plan(reference,&t.plan,reason,sizeof(reason)) && !is_plan) {
            fprintf(stderr,"Refused unsupported backup: %s\n",reason); return 1;
        }
        if (t.mode==OP_PROGRAM && !is_plan) {
            make_token(&t.plan,token);
            if (strcmp(argv[5],token)) { fputs("Refused: confirmation token must exactly match this backup's offline plan.\n",stderr); return 2; }
        }
    }
    if (report && create_report(&t,report)) goto finish;
    if (install_signal_handlers() || configure_output(&t)) {
        t.stdout_failed=1; goto finish;
    }
    t.deadline=now_seconds()+120;
    if (is_plan) {
        if (report_plan(&t,reference,reason,0)) goto finish;
        result=t.plan.state==DUBFIX_UNSUPPORTED?1:0;
        goto finish;
    }
    /* Held from before enumeration through hardware close and cleanup. */
    IOReturn power=IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep,
        kIOPMAssertionLevelOn,CFSTR("dubfix single-adapter diagnostic transaction"),&t.idle_assertion);
    if (power!=kIOReturnSuccess) {
        journal(&t,"ERROR: idle-sleep assertion acquisition failed=%08x; aborting before USB access.\n",(unsigned)power); goto finish;
    }
    t.idle_assertion_created=1;
    journal(&t,"Owned idle-system-sleep assertion acquired before USB access.\n");
    if (is_list) { result=list_devices(&t)?1:0; goto finish; }
    journal(&t,"MODE=%s. Hardware evidence is limited to two adapters; see docs/evidence.md.\n",argv[1]);
    if (backup) {
        if (report_plan(&t,reference,reason,1) ||
            save_file(&t,"reference.bin",reference,sizeof(reference)) ||
            save_file(&t,"candidate-expected.bin",t.plan.after,sizeof(t.plan.after)) || fsync(t.dir)) goto finish;
    }
    if (identity(&t,iface) || snapshot_controls(&t) || double_read(&t,first,second)) goto finish;
    if (t.mode==OP_BACKUP) {
        int supported=!dubfix_make_plan(first,&t.plan,reason,sizeof(reason));
        if (supported && memcmp(t.plan.mac,t.hardware_mac,6)) {
            t.plan.state=DUBFIX_UNSUPPORTED; supported=0;
            snprintf(reason,sizeof(reason),"NVM factory MAC does not match the hardware MAC");
        }
        if (save_file(&t,"backup.bin",first,sizeof(first)) || report_plan(&t,first,reason,1)) goto finish;
        if (supported && save_file(&t,"candidate-expected.bin",t.plan.after,sizeof(t.plan.after))) goto finish;
        journal(&t,"Backup saved privately. %s\n",supported?"The exact profile is supported.":"Unsupported layout: programming refused; raw dump retained for inspection.");
        result=supported?0:1; goto finish;
    }
    if (!memcmp(first,t.plan.after,OTP_BYTES)) {
        journal(&t,"Physical NVM already matches the exact expected image. No PROGRAM, staging, margin command or PG preparation is needed.\n");
        t.otp_verified=1;
        if (t.mode==OP_VERIFY) { result=runtime_report(&t)?1:0; goto finish; }
        result=0; goto finish;
    }
    if (memcmp(first,reference,OTP_BYTES) || t.plan.state!=DUBFIX_FIXABLE) {
        print_sha(&t,"Observed complete NVM",first,sizeof(first));
        journal(&t,"Refused: physical NVM matches neither this backup nor its exact expected image. No programming attempted.\n"); goto finish;
    }
    if (t.mode==OP_VERIFY) {
        journal(&t,"Verification failed: the stored four-byte fix is absent. No programming or PG preparation attempted.\n");
        (void)runtime_report(&t); goto finish;
    }
    t.baseline_valid=1;
    journal(&t,"Physical NVM matches the per-device backup; exact profile is fixable.\n");
    if (fresh_state(&t)) goto finish;
    if (t.mode==OP_PREFLIGHT) { result=0; goto finish; }
    if (prepare(&t)) goto finish;
    uint32_t blank_margin=0,blank_normal=0;
    if (read_word(&t,OTP_OFFSET,1,&blank_margin) || blank_margin!=0xffffffffu ||
        read_word(&t,OTP_OFFSET,0,&blank_normal) || blank_normal!=0xffffffffu ||
        read_all(&t,second) || memcmp(second,reference,OTP_BYTES)) {
        journal(&t,"Prepared-state blank-margin/normal/full-backup check failed margin=%08x normal=%08x.\n",blank_margin,blank_normal); goto finish;
    }
    journal(&t,"Prepared state: blank candidate margin+normalFFFFFFFF; full OTP remains unchanged.\n");
    if (t.mode==OP_DRY) {
        if (save_file(&t,"actual-dry-run.bin",second,sizeof(second))) goto finish;
        result=0; goto finish;
    }
    if (pulse(&t,t.plan.after)) goto finish;
    result=0;
finish:
    if (t.a && t.snapshot_valid && (t.dirty || t.selector_dirty)) {
        if (cleanup(&t)) result=1;
    }
    if (t.a && t.exclusive) {
        IOReturn closed=(*t.a->dev)->USBDeviceClose(t.a->dev);
        journal(&t,"USBDeviceClose=%08x (%s).\n",(unsigned)closed,mach_error_string(closed));
        if (closed!=kIOReturnSuccess) result=1;
    }
    if (t.a) close_device(t.a);
    if (t.idle_assertion_created) {
        IOReturn released=IOPMAssertionRelease(t.idle_assertion);
        journal(&t,"Owned idle-system-sleep assertion release=%08x after hardware cleanup/Close.\n",(unsigned)released);
        if (released!=kIOReturnSuccess) result=1;
        else t.idle_assertion_created=0;
    }
    journal(&t,"TRANSACTION STATE before final persistence: result=%d mode=%d stageAttempted=%d pulseAttempted=%d programIdleVerified=%d OTPverified=%d engineUnknown=%d normalReadCommands=%u marginReadCommands=%u interrupted=%d stdoutMirrorFailed=%d\n",
            result,t.mode,t.stage_attempted,t.pulse_attempted,t.program_idle_verified,t.otp_verified,t.engine_unknown,
            t.read_commands,t.margin_commands,(int)interrupted,t.stdout_failed);
    if (t.mode!=OP_PROGRAM && (t.stage_attempted || t.pulse_attempted)) result=1;
    if (interrupted || t.log_failed || t.stdout_failed) result=1;
    if (t.log>=0 && fsync(t.log)) { fputs("ERROR: final transaction-log fsync failed\n",stderr); result=1; }
    if (t.dir>=0 && fsync(t.dir)) { fputs("ERROR: final output-directory fsync failed\n",stderr); result=1; }
    if (t.log>=0 && close(t.log)) { fputs("ERROR: final transaction-log close failed\n",stderr); result=1; }
    if (t.dir>=0 && close(t.dir)) { fputs("ERROR: final output-directory close failed\n",stderr); result=1; }
    /* Absolutely no output follows restoring possibly-blocking FD flags. */
    if (restore_output(&t)) result=1;
    return result;
}
