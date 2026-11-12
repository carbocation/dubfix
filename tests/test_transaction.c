/* Synthetic offline fault-injection tests. No real transport backend is linked.
 * Includes production transaction functions; only transport/power API exports
 * below are fake. Fixture data is generated and is never a hardware backup.
 */
#define dubfix_step dubfix_test_cli_main
#define IOPMAssertionCreateWithName dubfix_test_power_create
#define IOPMAssertionRelease dubfix_test_power_release
#include "../src/dubfix.c"
#undef IOPMAssertionCreateWithName
#undef IOPMAssertionRelease
#undef dubfix_step
#include "fixture.h"
#include <dirent.h>

static unsigned fake_power_create_calls,fake_power_release_calls;
static int fake_power_failure;
static unsigned fake_enumerate_calls,fake_open_calls,fake_close_calls,fake_exclusive_open_calls,fake_exclusive_close_calls;
IOReturn dubfix_test_power_create(CFStringRef kind,IOPMAssertionLevel level,
                                  CFStringRef name,IOPMAssertionID *assertion)
{
    (void)kind; (void)level; (void)name; fake_power_create_calls++;
    if (fake_power_failure) return kIOReturnError;
    if (assertion) *assertion=123;
    return kIOReturnSuccess;
}
IOReturn dubfix_test_power_release(IOPMAssertionID assertion)
{ (void)assertion; fake_power_release_calls++; return kIOReturnSuccess; }

/* Fake transport only. No real device backend is linked into this binary. */
struct simulated_controller {
    uint32_t bank[2][0x4000];
    uint32_t neighbor_xor[2][0x4000];
    uint8_t otp[OTP_BYTES];
    unsigned requests,ins,outs,stage_writes,program_triggers,normal_reads,margin_reads;
    unsigned control_outs,phy_outs,selector_outs,bad_requests;
    int pending,busy_polls,busy_forever;
    uint16_t command;
    int fail_in_address,fail_in_nth,fail_in_seen,fail_in_persistent;
    int error_out_address,error_out_nth,error_out_seen;
    int error_out_value_enabled;
    uint32_t error_out_value;
    int interrupt_out_address;
    int pipe_fault_mode,pipe_read_fd,pipe_fault_applied,pipe_fault_error;
};
static struct simulated_controller sim;
static uint8_t fixture[OTP_BYTES];
static const uint8_t test_record[4]={0x20,0xe8,0x54,0x00};
static unsigned assertions,failures,cases;
static const char *case_name;
static char case_path[PATH_MAX];
/* Independent protocol oracle: deliberately do not derive these from regs[]. */
static const uint16_t expected_owned[6]={0x10,0xc0,0xc4,0x8000,0x1,0x8};
static const uint32_t expected_field[6]={0xff,0xff,0xff000000u,0xffff0000u,0xffff,0xffff};
static const uint16_t expected_bank[6]={0x100,0x100,0x100,0x100,0,0};
static const uint16_t expected_address[6]={0xe84c,0xe81c,0xe858,0xe0c8,0xcfd8,0xd848};
static const uint16_t expected_enables[6]={0x11,0x11,0x88,0xcc,0x33,0x33};
_Static_assert(N_REGS==6,"Audit independent protocol oracle when extending controls");

static int fill_stdout_pipe(void)
{
    uint8_t data[4096]; memset(data,'X',sizeof(data));
    for (unsigned count=0;count<1024;count++) {
        ssize_t n=write(STDOUT_FILENO,data,sizeof(data));
        if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return 0;
        if (n<0 && errno==EINTR) { count--; continue; }
        if (n<=0) return -1;
    }
    return -1;
}
static void apply_pipe_fault(void)
{
    sim.pipe_fault_applied=1;
    if (sim.pipe_fault_mode==1) {
        if (close(sim.pipe_read_fd)) sim.pipe_fault_error=1;
        sim.pipe_read_fd=-1;
    } else if (sim.pipe_fault_mode==2 && fill_stdout_pipe()) sim.pipe_fault_error=1;
}

static uint32_t *sim_word(uint16_t bank,uint16_t address)
{
    return &sim.bank[bank?1:0][address>>2];
}
static void sim_complete(void)
{
    unsigned index=sim.command&0x1ff;
    if (sim.pending==1) {
        OSWriteLittleInt32(sim_word(0x100,0xdd00),0,
                           OSReadLittleInt32(sim.otp,index*4));
    } else if (sim.pending==2) {
        uint32_t value=OSReadLittleInt32(sim.otp,index*4)&*sim_word(0x100,0xdd00);
        OSWriteLittleInt32(sim.otp,index*4,value);
    }
    *sim_word(0x100,0xdd04)=sim.command&~0xc000u;
    sim.pending=0;
}
static int sim_request(struct adapter *unused,uint8_t type,uint8_t req,uint16_t address,
                       uint16_t index,void *buffer,uint16_t len)
{
    (void)unused;
    sim.requests++;
    uint16_t bank=index&0x100,enable=index&0xff;
    if (req!=5 || len!=4 || (address&3) || (index&~0x1ffu) || !buffer ||
        (type!=0xc0 && type!=0x40) || (type==0xc0 && enable)) {
        sim.bad_requests++; return -1;
    }
    if (type==0xc0) {
        sim.ins++;
        if (sim.fail_in_address==address && ++sim.fail_in_seen>=sim.fail_in_nth &&
            (sim.fail_in_persistent || sim.fail_in_seen==sim.fail_in_nth)) return -1;
        if (bank==0x100 && address==0xdd04 && sim.pending) {
            if (!sim.busy_forever && sim.busy_polls--<=0) sim_complete();
        }
        OSWriteLittleInt32(buffer,0,*sim_word(bank,address));
        return 0;
    }
    sim.outs++;
    int expected_enable=-1;
    for (int i=0;i<6;i++)
        if (bank==expected_bank[i] && address==expected_address[i]) expected_enable=expected_enables[i];
    if (bank==0x100 && (address==0xe86c || address==0xb400 || address==0xb430 || address==0xdd04)) expected_enable=0x33;
    if (bank==0x100 && address==0xdd00) expected_enable=0xff;
    if (enable!=expected_enable) { sim.bad_requests++; return -1; }
    /* An independent owner changes neighbors AFTER production's IN snapshot.
     * Correct hardware byte enables must preserve this fresh value.
     */
    *sim_word(bank,address)^=sim.neighbor_xor[bank?1:0][address>>2];
    sim.neighbor_xor[bank?1:0][address>>2]=0;
    uint32_t value=OSReadLittleInt32(buffer,0),old=*sim_word(bank,address);
    for (unsigned b=0;b<4;b++) {
        if ((enable&(1u<<b)) && (enable&(0x10u<<b))) {
            uint32_t mask=0xffu<<(b*8);
            old=(old&~mask)|(value&mask);
        }
    }
    *sim_word(bank,address)=old;
    if (bank==0x100 && address==0xdd00) sim.stage_writes++;
    else if (bank==0x100 && address==0xdd04) {
        sim.command=(uint16_t)value;
        if ((value&0xfffffe00u)==0x8000u) { sim.normal_reads++; sim.pending=1; }
        else if (value==0x881b) { sim.margin_reads++; sim.pending=1; }
        else if (value==0x401b) { sim.program_triggers++; sim.pending=2; }
        else { sim.bad_requests++; return -1; }
        sim.busy_polls=1;
    } else if (bank==0x100 && address==0xe86c) sim.selector_outs++;
    else if (bank==0x100 && (address==0xb400 || address==0xb430)) sim.phy_outs++;
    else sim.control_outs++;
    if (sim.interrupt_out_address==address) interrupted=1;
    if (bank==0x100 && address==0xdd04 && value==0x401b && sim.pipe_fault_mode)
        apply_pipe_fault();
    /* Error is returned AFTER the fake hardware applied the OUT. */
    if (sim.error_out_address==address &&
        (!sim.error_out_value_enabled || sim.error_out_value==value) &&
        ++sim.error_out_seen==sim.error_out_nth) return -1;
    return 0;
}

/* All backend exports are fakes. The real transport_macos.c is not linked. */
static IOReturn fake_exclusive_open(void *self)
{ (void)self; fake_exclusive_open_calls++; return kIOReturnSuccess; }
static IOReturn fake_exclusive_close(void *self)
{ (void)self; fake_exclusive_close_calls++; return kIOReturnSuccess; }
static IOUSBDeviceInterface182 fake_usb_interface={
    .USBDeviceOpen=fake_exclusive_open,.USBDeviceClose=fake_exclusive_close
};
static IOUSBDeviceInterface182 *fake_usb_interface_pointer=&fake_usb_interface;
int find_adapters(struct adapter *list)
{
    fake_enumerate_calls++;
    memset(&list[0],0,sizeof(list[0]));
    list[0].usb=1; snprintf(list[0].name,sizeof(list[0].name),"test0");
    list[0].vid=0x2001; list[0].pid=0xb301; list[0].release=0x3100;
    list[0].version=0x7410; list[0].known=1; list[0].read_size=32764;
    list[0].ifnum=0; list[0].size_len=8;
    return 1;
}
int number_property(io_registry_entry_t entry,CFStringRef key,unsigned int *value)
{ (void)entry; (void)key; if (!value) return -1; *value=2; return 0; }
int open_device(struct adapter *adapter)
{ fake_open_calls++; adapter->dev=&fake_usb_interface_pointer; return 0; }
void close_device(struct adapter *adapter)
{ fake_close_calls++; adapter->dev=NULL; adapter->usb=0; }
int request(struct adapter *adapter,uint8_t type,uint8_t req,uint16_t value,
            uint16_t index,void *buffer,uint16_t length)
{ return sim_request(adapter,type,req,value,index,buffer,length); }
int identify_chip(struct adapter *adapter)
{
    uint8_t value[4];
    if (request(adapter,0xc0,5,0xe610,0x100,value,4)) return -1;
    adapter->version=OSReadLittleInt16(value,2)&0x7cf0;
    return 0;
}
int find_ncm(struct adapter *adapter)
{ adapter->ifnum=0; adapter->size_len=8; return 0; }
int get_size(struct adapter *adapter,unsigned int *size)
{ (void)adapter; if (!size) return -1; *size=12288; return 0; }

#define CHECK(condition) do { assertions++; if (!(condition)) { failures++; \
    fprintf(stderr,"ASSERT_FAIL %s:%d: %s\n",case_name,__LINE__,#condition); } } while (0)
static void set_reg_field(int i,uint16_t value)
{
    uint32_t *p=sim_word(regs[i].bank,regs[i].address);
    uint32_t shift=regs[i].shift*8,mask=(regs[i].width==1?0xffu:0xffffu)<<shift;
    *p=(*p&~mask)|((uint32_t)value<<shift);
}
static uint16_t get_reg_field(int i)
{ return reg_value(i,*sim_word(regs[i].bank,regs[i].address)); }
static void begin_case(const char *name,struct transaction *t,int mode)
{
    cases++; case_name=name; interrupted=0;
    fake_power_create_calls=fake_power_release_calls=0;
    fake_power_failure=0;
    fake_enumerate_calls=fake_open_calls=fake_close_calls=0;
    fake_exclusive_open_calls=fake_exclusive_close_calls=0;
    memset(&sim,0,sizeof(sim)); memcpy(sim.otp,fixture,sizeof(fixture));
    sim.fail_in_address=sim.error_out_address=sim.interrupt_out_address=-1;
    sim.pipe_read_fd=-1;
    memset(t,0,sizeof(*t)); t->mode=mode; t->dir=t->log=-1;
    t->identity_valid=t->snapshot_valid=t->baseline_valid=t->prepared=1;
    t->selector_valid=t->b400_valid=t->b430_valid=1;
    t->deadline=now_seconds()+120;
    char reason[256];
    CHECK(dubfix_make_plan(fixture,&t->plan,reason,sizeof(reason))==0);
    memcpy(t->hardware_mac,t->plan.mac,6); t->ntb_size=12288; t->driver_alloc=32764;
    memcpy(sim_word(0x100,0xc000),t->plan.mac,6);
    *sim_word(0x100,0xe610)=0x74100000;
    *sim_word(0x100,0xe854)=1;
    *sim_word(0,0xcfec)=0x00040000;
    const uint16_t values[N_REGS]={0x21,0xfe,0x02,0xa321,0xe555,0x0018};
    for (int i=0;i<N_REGS;i++) {
        *sim_word(regs[i].bank,regs[i].address)=0x5a3c1b27u;
        set_reg_field(i,values[i]); t->saved[i]=values[i];
    }
    *sim_word(0x100,0xe86c)=0x9182b000u; t->selector=0xb000;
    *sim_word(0x100,0xb400)=0x11221140u; t->b400=0x1140;
    *sim_word(0x100,0xb430)=0x33440055u; t->b430=0x0055;
    const char *temporary=getenv("DUBFIX_TEST_TMPDIR");
    if (!temporary || !*temporary) temporary="/tmp";
    snprintf(case_path,sizeof(case_path),"%s/case-%02u-XXXXXX",temporary,cases);
    CHECK(mkdtemp(case_path)!=NULL);
    t->dir=open(case_path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    CHECK(t->dir>=0);
    if (t->dir>=0) t->log=openat(t->dir,"journal.txt",O_WRONLY|O_CREAT|O_EXCL,0600);
    CHECK(t->log>=0);
    printf("CASE %u %s\n",cases,name);
}
static int remove_test_entry(int parent,const char *name)
{
    struct stat st;
    if (fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)) return -1;
    if (!S_ISDIR(st.st_mode)) return unlinkat(parent,name,0);
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (fd<0) return -1;
    DIR *listing=fdopendir(fd);
    if (!listing) { close(fd); return -1; }
    int failed=0; struct dirent *entry;
    while ((entry=readdir(listing))) {
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (remove_test_entry(fd,entry->d_name)) failed=1;
    }
    if (closedir(listing)) failed=1;
    if (unlinkat(parent,name,AT_REMOVEDIR)) failed=1;
    return failed?-1:0;
}
static void end_case(struct transaction *t)
{
    CHECK(sim.bad_requests==0);
    if (t->log>=0) { CHECK(fsync(t->log)==0); CHECK(close(t->log)==0); }
    if (t->dir>=0) {
        int duplicate=dup(t->dir); DIR *listing=duplicate<0?NULL:fdopendir(duplicate);
        CHECK(listing!=NULL);
        if (listing) {
            struct dirent *entry;
            while ((entry=readdir(listing))) {
                if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
                CHECK(remove_test_entry(t->dir,entry->d_name)==0);
            }
            CHECK(closedir(listing)==0);
        } else if (duplicate>=0) close(duplicate);
        CHECK(close(t->dir)==0);
        CHECK(rmdir(case_path)==0);
    }
}
static void enable_access(struct transaction *t)
{ CHECK(update_reg(t,R_E85B,(uint16_t)(t->saved[R_E85B]|0xc4))==0); }

static void test_nonprogram_gates(int mode)
{
    struct transaction t;
    const char *name=mode==OP_PREFLIGHT?"preflight-cannot-program-forged-flags":
        mode==OP_DRY?"dry-run-cannot-program-forged-flags":
        mode==OP_BACKUP?"backup-cannot-program-forged-flags":"verify-cannot-program-forged-flags";
    begin_case(name,&t,mode);
    CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e820)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0);
    t.stage_attempted=1;
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0);
    CHECK(sim.stage_writes==0 && sim.program_triggers==0 && sim.outs==0);
    end_case(&t);
}
static void test_command_allowlist(void)
{
    struct transaction t; begin_case("command-value-index-mask-mode-allowlist",&t,OP_PROGRAM);
    CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e821)!=0);
    CHECK(out4(&t,0x100,0xdd00,0x33,0x0054e820)!=0);
    CHECK(out4(&t,0,0xdd00,0xff,0x0054e820)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401a)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0xc01b)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x1401b)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x881c)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x8200)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x7fff)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0); /* no stage */
    CHECK(sim.outs==0 && !t.stage_attempted && !t.pulse_attempted);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x8000)==0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x81ff)==0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x881b)==0);
    CHECK(sim.normal_reads==2 && sim.margin_reads==1 && sim.program_triggers==0);
    end_case(&t);
}
static void test_margin_mode_gate(void)
{
    struct transaction t; begin_case("margin-read-requires-dry-mode-and-preparation",&t,OP_PREFLIGHT);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x881b)!=0);
    t.mode=OP_DRY; t.prepared=0;
    CHECK(out4(&t,0x100,0xdd04,0x33,0x881b)!=0);
    t.prepared=1;
    CHECK(out4(&t,0x100,0xdd04,0x33,0x881b)==0);
    CHECK(sim.margin_reads==1 && sim.program_triggers==0);
    end_case(&t);
}
static void test_program_once(void)
{
    struct transaction t; begin_case("single-program-trigger-and-stage-no-retry",&t,OP_PROGRAM);
    CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e820)==0);
    CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e820)!=0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)==0);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0);
    CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e820)!=0);
    CHECK(t.stage_attempted==1 && t.pulse_attempted==1 && t.finishing==1);
    CHECK(sim.stage_writes==1 && sim.program_triggers==1);
    end_case(&t);
}
static void test_read_all(void)
{
    struct transaction t; uint8_t data[OTP_BYTES];
    begin_case("full-normal-read-physical-indexes-and-access-cleanup",&t,OP_PREFLIGHT);
    enable_access(&t);
    CHECK(read_all(&t,data)==0);
    CHECK(!memcmp(data,fixture,sizeof(data)) && t.last_read_bytes==OTP_BYTES);
    CHECK(sim.normal_reads==512 && t.read_commands==512 && sim.margin_reads==0);
    CHECK(sim.stage_writes==0 && sim.program_triggers==0);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    CHECK(get_reg_field(R_E85B)==t.saved[R_E85B]);
    end_case(&t);
}
static void test_partial_read_failure(void)
{
    struct transaction t; uint8_t data[OTP_BYTES]; memset(data,0x6a,sizeof(data));
    begin_case("partial-read-data-not-invented-after-in-failure",&t,OP_PREFLIGHT);
    enable_access(&t);
    sim.fail_in_address=0xdd00; sim.fail_in_nth=3;
    CHECK(read_all(&t,data)!=0);
    CHECK(t.last_read_bytes==8 && !memcmp(data,fixture,8));
    CHECK(data[8]==0x6a && data[OTP_BYTES-1]==0x6a);
    CHECK(sim.normal_reads==3 && sim.program_triggers==0);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    end_case(&t);
}
static void prepare_dirty_state(struct transaction *t)
{
    t->prepared=0;
    CHECK(prepare(t)==0 && t->prepared);
    CHECK(t->b400_dirty && t->b430_dirty && t->cfg_dirty[R_E85B]);
}
static void test_prepare_cleanup(void)
{
    struct transaction t; begin_case("dry-prepare-restore-including-phy-selector",&t,OP_DRY);
    prepare_dirty_state(&t);
    CHECK((*sim_word(0x100,0xb400)&0xffff)==0x1800);
    CHECK((*sim_word(0x100,0xe86c)&0xffff)==t.selector);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    CHECK((*sim_word(0x100,0xb400)&0xffff)==t.b400);
    CHECK((*sim_word(0x100,0xb430)&4)==(t.b430&4));
    CHECK((*sim_word(0x100,0xe86c)&0xffff)==t.selector);
    CHECK(sim.stage_writes==0 && sim.program_triggers==0);
    end_case(&t);
}
static void test_read_busy_cleanup(void)
{
    struct transaction t; begin_case("read-only-stuck-busy-still-bounded-restores-controls",&t,OP_DRY);
    prepare_dirty_state(&t);
    sim.pending=1; sim.command=0x801b; sim.busy_forever=1;
    *sim_word(0x100,0xdd04)=0x801b;
    unsigned before_outs=sim.outs; double start=now_seconds();
    CHECK(cleanup(&t)!=0); /* Final engine idle cannot be verified. */
    CHECK(now_seconds()-start<5 && !t.engine_unknown);
    CHECK(sim.outs>before_outs && sim.phy_outs>=4);
    CHECK(get_reg_field(R_E85B)==t.saved[R_E85B]);
    CHECK((*sim_word(0x100,0xb400)&0xffff)==t.b400);
    CHECK(sim.program_triggers==0 && sim.stage_writes==0);
    end_case(&t);
}
static void test_read_status_in_failure_cleanup(void)
{
    struct transaction t; begin_case("read-only-status-in-failure-restores-without-command-replay",&t,OP_DRY);
    prepare_dirty_state(&t);
    sim.fail_in_address=0xdd04; sim.fail_in_nth=1; sim.fail_in_persistent=1;
    unsigned before_outs=sim.outs,reads=sim.normal_reads;
    CHECK(cleanup(&t)!=0 && !t.engine_unknown);
    CHECK(sim.outs>before_outs && sim.normal_reads==reads);
    CHECK(get_reg_field(R_E85B)==t.saved[R_E85B]);
    CHECK((*sim_word(0x100,0xb400)&0xffff)==t.b400);
    CHECK(sim.program_triggers==0 && sim.stage_writes==0);
    end_case(&t);
}
static void test_program_uncertainty(int kind)
{
    struct transaction t;
    const char *name=kind==0?"observed-program-bit-prevents-all-cleanup":
        kind==1?"post-pulse-busy-prevents-all-cleanup":"post-pulse-in-failure-prevents-all-cleanup";
    begin_case(name,&t,OP_DRY); prepare_dirty_state(&t);
    if (kind) t.pulse_attempted=1;
    if (kind==2) { sim.fail_in_address=0xdd04; sim.fail_in_nth=1; sim.fail_in_persistent=1; }
    else *sim_word(0x100,0xdd04)=0x401b;
    unsigned before=sim.outs;
    CHECK(cleanup(&t)!=0 && t.engine_unknown);
    CHECK(sim.outs==before); /* No clock/power/access/PHY write. */
    if (kind!=2) CHECK(t.program_bit_observed);
    CHECK(get_reg_field(R_E85B)==(uint16_t)(t.saved[R_E85B]|0xc4));
    CHECK((*sim_word(0x100,0xb400)&0xffff)==0x1800);
    end_case(&t);
}
static void test_masked_restore(void)
{
    struct transaction t; begin_case("cleanup-preserves-unowned-bits-and-neighbor-bytes",&t,OP_DRY);
    prepare_dirty_state(&t);
    uint16_t before[N_REGS],expected[N_REGS]; uint32_t neighbors[N_REGS];
    for (int i=0;i<N_REGS;i++) {
        uint16_t fieldmax=(i==R_E84C || i==R_E81C || i==R_E85B)?0xff:0xffff;
        before[i]=(uint16_t)(get_reg_field(i)^(fieldmax&~expected_owned[i]));
        set_reg_field(i,before[i]);
        expected[i]=(uint16_t)((before[i]&~expected_owned[i])|(t.saved[i]&expected_owned[i]));
        uint32_t field=expected_field[i];
        uint32_t *p=sim_word(expected_bank[i],expected_address[i]);
        *p^=0x13371337u&~field;
        uint32_t late_change=0x45126789u&~field;
        neighbors[i]=(*p^late_change)&~field;
        sim.neighbor_xor[expected_bank[i]?1:0][expected_address[i]>>2]=late_change;
    }
    uint16_t b430before=(uint16_t)(*sim_word(0x100,0xb430)^0x0551u);
    *sim_word(0x100,0xb430)=0xabcd0000u|b430before;
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    for (int i=0;i<N_REGS;i++) {
        uint32_t field=expected_field[i];
        CHECK(get_reg_field(i)==expected[i]);
        CHECK((*sim_word(expected_bank[i],expected_address[i])&~field)==neighbors[i]);
    }
    CHECK((*sim_word(0x100,0xb430)&0xffff)==((b430before&~4u)|(t.b430&4u)));
    CHECK((*sim_word(0x100,0xb430)&0xffff0000u)==0xabcd0000u);
    CHECK(sim.program_triggers==0);
    end_case(&t);
}
static void test_read_out_ack_ambiguity(void)
{
    struct transaction t; uint32_t value;
    begin_case("read-out-error-after-hardware-action-still-restores",&t,OP_DRY);
    prepare_dirty_state(&t);
    sim.error_out_address=0xdd04; sim.error_out_nth=1;
    sim.error_out_value_enabled=1; sim.error_out_value=0x801b;
    CHECK(read_word(&t,OTP_OFFSET,0,&value)!=0 && sim.pending==1);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    CHECK(sim.normal_reads==1 && sim.program_triggers==0);
    CHECK(get_reg_field(R_E85B)==t.saved[R_E85B]);
    end_case(&t);
}
static void test_stage_out_ack_ambiguity(void)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case("stage-out-error-after-action-never-triggers-program",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    sim.error_out_address=0xdd00; sim.error_out_nth=1;
    CHECK(pulse(&t,expected)!=0);
    CHECK(t.stage_attempted && !t.pulse_attempted);
    CHECK(sim.stage_writes==1 && sim.program_triggers==0 && !memcmp(sim.otp,fixture,OTP_BYTES));
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    end_case(&t);
}
static void test_trigger_out_ack_ambiguity(void)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case("program-out-error-after-action-no-read-or-pulse-retry",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    sim.error_out_address=0xdd04; sim.error_out_nth=1;
    sim.error_out_value_enabled=1; sim.error_out_value=0x401b;
    CHECK(pulse(&t,expected)!=0);
    CHECK(t.stage_attempted && t.pulse_attempted && t.program_idle_verified && !t.otp_verified);
    CHECK(sim.stage_writes==1 && sim.program_triggers==1 && sim.normal_reads==0 && sim.margin_reads==0);
    CHECK(!memcmp(sim.otp,expected,OTP_BYTES)); /* Error acknowledgement did NOT undo fake OTP action. */
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0 && sim.program_triggers==1);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    end_case(&t);
}
static void test_successful_program_model(void)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case("successful-fake-pulse-verifies-only-one-dword-and-entire-image",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    CHECK(pulse(&t,expected)==0 && t.otp_verified && t.program_idle_verified);
    CHECK(sim.stage_writes==1 && sim.program_triggers==1 && sim.margin_reads==1 && sim.normal_reads==513);
    CHECK(!memcmp(sim.otp,expected,OTP_BYTES));
    CHECK(cleanup(&t)==0);
    end_case(&t);
}
static void test_program_completion_failure(int timeout)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case(timeout?"actual-pulse-busy-timeout-freezes-controls-no-retries":
                      "actual-pulse-status-in-failure-freezes-controls-no-retries",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    if (timeout) sim.busy_forever=1;
    else { sim.fail_in_address=0xdd04; sim.fail_in_nth=2; sim.fail_in_persistent=1; }
    double start=now_seconds();
    CHECK(pulse(&t,expected)!=0);
    CHECK(t.stage_attempted && t.pulse_attempted && t.engine_unknown && !t.program_idle_verified);
    CHECK(now_seconds()-start<15);
    CHECK(sim.stage_writes==1 && sim.program_triggers==1 && sim.normal_reads==0 && sim.margin_reads==0);
    unsigned before=sim.outs;
    CHECK(cleanup(&t)!=0 && sim.outs==before);
    CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0 && sim.program_triggers==1);
    CHECK(get_reg_field(R_E85B)==(uint16_t)(t.saved[R_E85B]|0xc4));
    end_case(&t);
}
static void test_prepare_phy_out_ambiguity(void)
{
    struct transaction t; begin_case("partial-prepare-phy-out-error-after-action-restores-saved-state",&t,OP_DRY);
    t.prepared=0;
    sim.error_out_address=0xb400; sim.error_out_nth=1;
    CHECK(prepare(&t)!=0 && !t.prepared);
    CHECK(t.b400_dirty && (*sim_word(0x100,0xb400)&0xffff)==0x1800);
    CHECK((*sim_word(0x100,0xe86c)&0xffff)==t.selector);
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    CHECK((*sim_word(0x100,0xb400)&0xffff)==t.b400);
    CHECK(sim.stage_writes==0 && sim.program_triggers==0);
    end_case(&t);
}
static void test_failed_durable_journal(void)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case("pulse-needs-durable-journal-before-any-stage",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    CHECK(close(t.log)==0); t.log=-1;
    CHECK(pulse(&t,expected)!=0);
    CHECK(!t.stage_attempted && !t.pulse_attempted && sim.stage_writes==0 && sim.program_triggers==0);
    CHECK(cleanup(&t)==0);
    end_case(&t);
}
static void test_signal_boundaries(int after_trigger)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case(after_trigger?"signal-after-trigger-finishes-bounded-verification-without-second-pulse":
                             "signal-after-stage-prevents-trigger-and-allows-safe-cleanup",&t,OP_PROGRAM);
    enable_access(&t); memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
    sim.interrupt_out_address=after_trigger?0xdd04:0xdd00;
    int result=pulse(&t,expected);
    CHECK(interrupted && t.stage_attempted && sim.stage_writes==1);
    if (after_trigger) {
        CHECK(result==0 && t.pulse_attempted && t.program_idle_verified && t.otp_verified);
        CHECK(sim.program_triggers==1 && !memcmp(sim.otp,expected,OTP_BYTES));
        CHECK(sim.margin_reads==1 && sim.normal_reads==513);
    } else {
        CHECK(result!=0 && !t.pulse_attempted && !t.otp_verified);
        CHECK(sim.program_triggers==0 && !memcmp(sim.otp,fixture,OTP_BYTES));
    }
    CHECK(cleanup(&t)==0 && t.cleanup_verified);
    end_case(&t);
}
static void test_cli_gate(void)
{
    struct transaction t; begin_case("missing-or-wrong-ack-exits-before-backup-or-device-access",&t,OP_PREFLIGHT);
    char backup[PATH_MAX],report[PATH_MAX];
    snprintf(backup,sizeof(backup),"%s/synthetic-backup.bin",case_path);
    snprintf(report,sizeof(report),"%s/report-not-created",case_path);
    CHECK(save_file(&t,"synthetic-backup.bin",fixture,OTP_BYTES)==0);
    char *missing[]={"dubfix","apply","test0",backup,report,NULL};
    char *wrong[]={"dubfix","apply","test0",backup,report,"WRONG",NULL};
    CHECK(dubfix_test_cli_main(5,missing)==2);
    CHECK(dubfix_test_cli_main(6,wrong)==2);
    CHECK(sim.requests==0 && sim.outs==0);
    CHECK(fake_power_create_calls==0 && fake_enumerate_calls==0 && fake_open_calls==0);
    struct stat st; CHECK(lstat(report,&st)!=0 && errno==ENOENT);
    end_case(&t);
}
static void test_plan_state_gate(void)
{
    struct transaction t; uint8_t expected[OTP_BYTES];
    begin_case("already-fixed-or-unsupported-plan-cannot-stage-or-pulse",&t,OP_PROGRAM);
    memcpy(expected,t.plan.after,sizeof(expected));
    const enum dubfix_profile_state states[]={DUBFIX_ALREADY_FIXED,DUBFIX_UNSUPPORTED};
    for (size_t i=0;i<sizeof(states)/sizeof(states[0]);i++) {
        t.plan.state=states[i];
        CHECK(out4(&t,0x100,0xdd00,0xff,0x0054e820)!=0);
        t.stage_attempted=1;
        CHECK(out4(&t,0x100,0xdd04,0x33,0x401b)!=0);
        CHECK(pulse(&t,expected)!=0);
        t.stage_attempted=0;
    }
    CHECK(sim.stage_writes==0 && sim.program_triggers==0 && sim.outs==0);
    end_case(&t);
}
enum cli_fault { CLI_WRONG_MAC,CLI_NVM_DRIFT,CLI_ALREADY_FIXED,CLI_UNKNOWN_PROFILE,CLI_POWER_FAILURE,CLI_ALREADY_FIXED_BACKUP };
static void test_cli_profile_binding(enum cli_fault fault)
{
    static const char *names[]={
        "cli-refuses-backup-for-different-hardware-mac",
        "cli-refuses-physical-nvm-drift-from-backup-and-expected-image",
        "cli-apply-is-noop-when-physical-image-already-exactly-fixed",
        "cli-refuses-unknown-profile-before-power-or-device-access",
        "cli-sleep-assertion-failure-aborts-before-enumeration",
        "cli-already-fixed-backup-is-idempotent-no-program"
    };
    struct transaction t; begin_case(names[fault],&t,OP_PROGRAM);
    uint8_t backup_data[OTP_BYTES]; memcpy(backup_data,fixture,sizeof(backup_data));
    if (fault==CLI_WRONG_MAC) ((uint8_t *)sim_word(0x100,0xc000))[5]^=0x01;
    if (fault==CLI_NVM_DRIFT) sim.otp[DUBFIX_MAIN_BYTES+16]^=0x01;
    if (fault==CLI_ALREADY_FIXED || fault==CLI_ALREADY_FIXED_BACKUP) {
        memcpy(sim.otp,t.plan.after,OTP_BYTES); *sim_word(0x100,0xe854)=0;
    }
    if (fault==CLI_ALREADY_FIXED_BACKUP) memcpy(backup_data,t.plan.after,OTP_BYTES);
    if (fault==CLI_UNKNOWN_PROFILE) backup_data[0]^=0x40;
    if (fault==CLI_POWER_FAILURE) fake_power_failure=1;
    struct dubfix_plan backup_plan; char reason[256],token[TOKEN_BYTES];
    if (fault!=CLI_UNKNOWN_PROFILE) {
        CHECK(dubfix_make_plan(backup_data,&backup_plan,reason,sizeof(reason))==0);
        make_token(&backup_plan,token);
    } else snprintf(token,sizeof(token),"INVALID-FOR-UNSUPPORTED-PROFILE");
    CHECK(save_file(&t,"synthetic-backup.bin",backup_data,sizeof(backup_data))==0);
    char backup[PATH_MAX],report[PATH_MAX];
    snprintf(backup,sizeof(backup),"%s/synthetic-backup.bin",case_path);
    snprintf(report,sizeof(report),"%s/cli-report",case_path);
    char *argv[]={"dubfix","apply","test0",backup,report,token,NULL};
    int result=dubfix_test_cli_main(6,argv);
    CHECK(result==((fault==CLI_ALREADY_FIXED || fault==CLI_ALREADY_FIXED_BACKUP)?0:1));
    CHECK(sim.program_triggers==0 && sim.stage_writes==0 && sim.margin_reads==0);
    CHECK(sim.phy_outs==0); /* No PG preparation; PHY snapshot is IN+selector only. */
    if (fault==CLI_UNKNOWN_PROFILE) {
        CHECK(fake_power_create_calls==0 && fake_enumerate_calls==0 && sim.requests==0);
    } else if (fault==CLI_POWER_FAILURE) {
        CHECK(fake_power_create_calls==1 && fake_power_release_calls==0 && fake_enumerate_calls==0 && sim.requests==0);
    } else {
        CHECK(fake_power_create_calls==1 && fake_power_release_calls==1 && fake_enumerate_calls==1);
        if (fault==CLI_WRONG_MAC) CHECK(sim.normal_reads==0 && fake_exclusive_open_calls==0);
        else CHECK(sim.normal_reads==1024 && fake_exclusive_open_calls==1 && fake_exclusive_close_calls==1);
        CHECK(get_reg_field(R_E85B)==t.saved[R_E85B]);
        CHECK((*sim_word(0x100,0xe86c)&0xffff)==t.selector);
    }
    end_case(&t);
}
struct mirror_child_result {
    int pulse_result,cleanup_result,program_verified,idle_verified,stdout_failed,log_failed;
    unsigned stage_writes,program_triggers,normal_reads,margin_reads,bad_requests;
    int pipe_fault_applied,pipe_fault_error,signals_ok,nonblocking_ok,owned_restore_ok;
};
static void test_output_pipe(int filled,int after_trigger)
{
    struct transaction t;
    const char *name=filled?
        (after_trigger?"full-stdout-pipe-after-trigger-cannot-stall-completion-or-local-journal":
                       "full-stdout-pipe-before-trigger-blocks-program-and-restores"):
        (after_trigger?"closed-stdout-pipe-after-trigger-cannot-kill-completion-or-local-journal":
                       "closed-stdout-pipe-before-trigger-blocks-program-and-restores");
    begin_case(name,&t,OP_PROGRAM);
    int channel[2]={-1,-1}; CHECK(pipe(channel)==0);
    CHECK(fflush(NULL)==0);
    pid_t child=fork(); CHECK(child>=0);
    if (child==0) {
        struct mirror_child_result result={0};
        uint8_t expected[OTP_BYTES]; memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
        /* The parent closes its read descriptor. Child alone owns the reader,
         * which is never drained and can be closed precisely after fake pulse.
         */
        if (dup2(channel[1],STDOUT_FILENO)<0 || dup2(channel[1],STDERR_FILENO)<0) _exit(90);
        close(channel[1]); clearerr(stdout); clearerr(stderr);
        struct sigaction original={0}; original.sa_handler=SIG_DFL;
        sigemptyset(&original.sa_mask); sigaction(SIGPIPE,&original,NULL);
        result.signals_ok=install_signal_handlers()==0;
        if (!result.signals_ok || configure_output(&t)) _exit(91);
        result.nonblocking_ok=!!(fcntl(STDOUT_FILENO,F_GETFL)&O_NONBLOCK) &&
                              !!(fcntl(STDERR_FILENO,F_GETFL)&O_NONBLOCK);
        sim.pipe_read_fd=channel[0]; sim.pipe_fault_mode=filled?2:1;
        if (!after_trigger) apply_pipe_fault();
        /* This access change and all subsequent controller calls are fake. */
        if (update_reg(&t,R_E85B,(uint16_t)(t.saved[R_E85B]|0xc4))) _exit(92);
        result.pulse_result=pulse(&t,expected);
        result.cleanup_result=cleanup(&t);
        result.program_verified=t.otp_verified; result.idle_verified=t.program_idle_verified;
        result.stdout_failed=t.stdout_failed; result.log_failed=t.log_failed;
        result.stage_writes=sim.stage_writes; result.program_triggers=sim.program_triggers;
        result.normal_reads=sim.normal_reads; result.margin_reads=sim.margin_reads;
        result.bad_requests=sim.bad_requests;
        result.pipe_fault_applied=sim.pipe_fault_applied; result.pipe_fault_error=sim.pipe_fault_error;
        result.owned_restore_ok=get_reg_field(R_E85B)==t.saved[R_E85B];
        journal(&t,"OFFLINE child completed after mirrored-output fault; fake triggers=%u cleanup=%d\n",
                sim.program_triggers,result.cleanup_result);
        if (fsync(t.log) || fsync(t.dir)) _exit(93);
        int fd=openat(t.dir,"pipe-child-result.bin",O_WRONLY|O_CREAT|O_EXCL,0600);
        if (fd<0 || write(fd,&result,sizeof(result))!=(ssize_t)sizeof(result) || fsync(fd) || close(fd)) _exit(94);
        if (sim.pipe_read_fd>=0) close(sim.pipe_read_fd);
        _exit(0);
    }
    close(channel[0]); close(channel[1]);
    if (child>0) {
        int status=0,done=0; double deadline=now_seconds()+5;
        while (now_seconds()<deadline) {
            pid_t r=waitpid(child,&status,WNOHANG);
            if (r==child) { done=1; break; }
            if (r<0) break;
            usleep(10000);
        }
        if (!done) { kill(child,SIGKILL); waitpid(child,&status,0); }
        CHECK(done && WIFEXITED(status) && WEXITSTATUS(status)==0);
        struct mirror_child_result result={0};
        int fd=openat(t.dir,"pipe-child-result.bin",O_RDONLY|O_NOFOLLOW);
        CHECK(fd>=0);
        if (fd>=0) {
            CHECK(read(fd,&result,sizeof(result))==(ssize_t)sizeof(result)); CHECK(close(fd)==0);
            CHECK(result.signals_ok && result.nonblocking_ok && result.pipe_fault_applied && !result.pipe_fault_error);
            CHECK(result.stdout_failed && !result.log_failed && result.owned_restore_ok && result.cleanup_result==0);
            CHECK(result.bad_requests==0);
            if (after_trigger) {
                CHECK(result.pulse_result==0 && result.program_verified && result.idle_verified);
                CHECK(result.stage_writes==1 && result.program_triggers==1 && result.margin_reads==1 && result.normal_reads==513);
                uint8_t saved[OTP_BYTES],expected[OTP_BYTES];
                memcpy(expected,fixture,sizeof(expected)); memcpy(expected+OTP_OFFSET,test_record,4);
                int image=openat(t.dir,"post-program-verified.bin",O_RDONLY|O_NOFOLLOW);
                CHECK(image>=0);
                if (image>=0) {
                    CHECK(read(image,saved,sizeof(saved))==OTP_BYTES && !memcmp(saved,expected,sizeof(saved)));
                    CHECK(close(image)==0);
                }
            } else CHECK(result.pulse_result!=0 && result.program_triggers==0 && !result.program_verified);
            char local_log[16384]={0};
            int logread=openat(t.dir,"journal.txt",O_RDONLY|O_NOFOLLOW);
            CHECK(logread>=0);
            if (logread>=0) {
                CHECK(read(logread,local_log,sizeof(local_log)-1)>0);
                CHECK(strstr(local_log,"OFFLINE child completed after mirrored-output fault")!=NULL);
                if (after_trigger) CHECK(strstr(local_log,"Exactly20e85400 at006c changed")!=NULL);
                CHECK(close(logread)==0);
            }
        }
    }
    end_case(&t);
}
int main(void)
{
    dubfix_test_fixture(fixture);
    struct dubfix_plan fixture_plan; char reason[256];
    if (dubfix_make_plan(fixture,&fixture_plan,reason,sizeof(reason)) || fixture_plan.state!=DUBFIX_FIXABLE) {
        fprintf(stderr,"Synthetic fixture rejected: %s\n",reason); return 2;
    }
    test_nonprogram_gates(OP_PREFLIGHT); test_nonprogram_gates(OP_DRY);
    test_nonprogram_gates(OP_BACKUP); test_nonprogram_gates(OP_VERIFY);
    test_command_allowlist(); test_margin_mode_gate(); test_program_once();
    test_read_all(); test_partial_read_failure(); test_prepare_cleanup();
    test_read_busy_cleanup(); test_read_status_in_failure_cleanup();
    test_program_uncertainty(0); test_program_uncertainty(1); test_program_uncertainty(2);
    test_masked_restore(); test_read_out_ack_ambiguity(); test_stage_out_ack_ambiguity();
    test_trigger_out_ack_ambiguity(); test_successful_program_model(); test_cli_gate();
    test_program_completion_failure(1); test_program_completion_failure(0);
    test_prepare_phy_out_ambiguity(); test_failed_durable_journal();
    test_signal_boundaries(0); test_signal_boundaries(1);
    test_output_pipe(0,0); test_output_pipe(1,0);
    test_output_pipe(0,1); test_output_pipe(1,1);
    test_plan_state_gate();
    test_cli_profile_binding(CLI_WRONG_MAC); test_cli_profile_binding(CLI_NVM_DRIFT);
    test_cli_profile_binding(CLI_ALREADY_FIXED); test_cli_profile_binding(CLI_UNKNOWN_PROFILE);
    test_cli_profile_binding(CLI_POWER_FAILURE); test_cli_profile_binding(CLI_ALREADY_FIXED_BACKUP);
    printf("DUBFIX_TRANSACTION_TEST_RESULT cases=%u assertions=%u failures=%u actual_device_calls=0\n",cases,assertions,failures);
    return failures?1:0;
}
