/* Offline tests for the check/fix/verify front end. The steps it would run as
 * child processes are replaced by a scripted fake, so no USB device, real
 * backup or child process is involved. */
#define main dubfix_test_front_main
#include "../src/cli.c"
#undef main

static unsigned assertions,failures;
#define CHECK(x) do { assertions++; if (!(x)) { failures++; fprintf(stderr,"FAILED %s:%d: %s\n",__FILE__,__LINE__,#x); } } while (0)

int dubfix_step(int argc,char **argv) { (void)argc; (void)argv; return 99; }

enum { APPLY_OK, APPLY_REFUSED_EARLY, APPLY_UNCERTAIN, APPLY_KILLED };
static struct {
    int adapters,wrong_hardware,unsupported_layout,backup_fails,dry_run_fails;
    int stored,active,apply_mode;
    int lists,backups,plans,preflights,dry_runs,applies,verifies;
    char token[200],iface[16];
} world;

static void write_file(const char *dir,const char *name,const char *text)
{
    char path[PATH_BYTES*2]; snprintf(path,sizeof(path),"%s/%s",dir,name);
    FILE *f=fopen(path,"w"); CHECK(f!=NULL);
    if (f) { fputs(text,f); fclose(f); }
}
static void write_log(const char *dir,const char *extra,int stage,int pulse,int stored)
{
    char text[512];
    snprintf(text,sizeof(text),"%sTRANSACTION STATE before final persistence: result=0 mode=0 stageAttempted=%d pulseAttempted=%d programIdleVerified=0 OTPverified=%d engineUnknown=0\n",
             extra,stage,pulse,stored);
    CHECK(mkdir(dir,0700)==0);
    write_file(dir,"transaction.log",text);
}
static int fake_step(char *const args[],char *capture,size_t size)
{
    const char *step=args[0];
    if (!strcmp(step,"list")) {
        world.lists++;
        size_t used=(size_t)snprintf(capture,size,"Owned idle-system-sleep assertion acquired before USB access.\n");
        for (int i=0;i<world.adapters;i++)
            used+=(size_t)snprintf(capture+used,size-used,
                "test%d hardwareMAC=02:11:22:33:44:5%d USB=2001:b301 release=3100 chip=%s configuration=2 NTB=12288 driverAllocation=32764 profileHardware=%s\n",
                i,5+i,world.wrong_hardware?"7420":"7410",world.wrong_hardware?"unsupported/unreadable":"candidate (backup required)");
        if (!world.adapters) snprintf(capture+used,size-used,"No D-Link 2001:b301 adapter attached to the Apple NCM driver.\n");
        return world.wrong_hardware?1:0;
    }
    if (!strcmp(step,"backup")) {
        world.backups++;
        if (world.backup_fails) { write_log(args[2],"Refused: two complete physical NVM reads disagree.\n",0,0,0); return 1; }
        write_log(args[2],"",0,0,0); write_file(args[2],"backup.bin","synthetic");
        return world.unsupported_layout?1:0;
    }
    if (!strcmp(step,"plan")) {
        world.plans++;
        if (world.unsupported_layout) {
            snprintf(capture,size,"dubfix profile-v1\nClassification: unsupported\nReason: unknown factory record stream\n");
            return 1;
        }
        snprintf(capture,size,"dubfix profile-v1\nClassification: fixable\nReason: supported\nConfirmation token: SYNTHETIC-TOKEN\n");
        return 0;
    }
    snprintf(world.iface,sizeof(world.iface),"%s",args[1]);
    if (!strcmp(step,"preflight")) { world.preflights++; write_log(args[3],"",0,0,world.stored); return 0; }
    if (!strcmp(step,"dry-run")) {
        world.dry_runs++;
        write_log(args[3],world.dry_run_fails?"Prepared-state blank-margin/normal/full-backup check failed.\n":"",0,0,0);
        return world.dry_run_fails;
    }
    if (!strcmp(step,"apply")) {
        world.applies++; snprintf(world.token,sizeof(world.token),"%s",args[4]?args[4]:"");
        if (world.apply_mode==APPLY_OK) { world.stored=1; write_log(args[3],"",1,1,1); return 0; }
        if (world.apply_mode==APPLY_REFUSED_EARLY) { write_log(args[3],"Refused fresh-device preparation.\n",0,0,0); return 1; }
        if (world.apply_mode==APPLY_UNCERTAIN) { write_log(args[3],"ERROR: program completion is unknown.\n",1,1,0); return 1; }
        CHECK(mkdir(args[3],0700)==0); write_file(args[3],"transaction.log","Next operation stages0054e820\n");
        return -1;
    }
    if (!strcmp(step,"verify")) {
        world.verifies++; write_log(args[3],"",0,0,world.stored);
        return world.stored && world.active?0:1;
    }
    CHECK(!"unexpected step");
    return -1;
}
static int run(const char *command,const char *iface,const char *typed)
{
    char *argv[]={"dubfix",(char *)command,(char *)iface,NULL};
    char input[64]; snprintf(input,sizeof(input),"%s",typed?typed:"");
    answers=fmemopen(input,strlen(input)+1,"r");
    stop_requested=0;
    int result=dubfix_test_front_main(iface?3:2,argv);
    fclose(answers); answers=NULL;
    return result;
}
static void begin(const char *name)
{
    static unsigned serial;
    const char *base=getenv("DUBFIX_TEST_TMPDIR"); char path[PATH_BYTES];
    snprintf(path,sizeof(path),"%s/cli-%u",base?base:"/nonexistent",++serial);
    CHECK(mkdir(path,0700)==0 && chdir(path)==0);
    memset(&world,0,sizeof(world)); world.adapters=1;
    printf("--- %s\n",name);
}

static void test_parsers(void)
{
    struct found f; struct outcome o;
    CHECK(parse_list_line("en7 hardwareMAC=02:11:22:33:44:55 USB=2001:b301 profileHardware=candidate (backup required)",&f)==0 &&
          f.supported && !strcmp(f.iface,"en7") && !strcmp(f.mac,"02:11:22:33:44:55"));
    CHECK(parse_list_line("en7 hardwareMAC=unreadable USB=2001:b301 profileHardware=unsupported/unreadable",&f)==0 && !f.supported);
    CHECK(parse_list_line("en7 hardwareMAC=unreadable USB=2001:b301 profileHardware=candidate (backup required)",&f)==0 && !f.supported);
    CHECK(parse_list_line("Owned idle-system-sleep assertion acquired before USB access.",&f)==-1);
    CHECK(parse_list_line("TRANSACTION STATE before final persistence: result=0",&f)==-1);
    o=parse_outcome("x\nTRANSACTION STATE: stageAttempted=1 pulseAttempted=1 OTPverified=0\n");
    CHECK(o.found && o.stage==1 && o.pulse==1 && o.stored==0);
    o=parse_outcome("Next operation stages\n"); CHECK(!o.found);
    o=parse_outcome(NULL); CHECK(!o.found);
    o=parse_outcome("TRANSACTION STATE: truncated"); CHECK(o.found && o.stage==-1 && o.pulse==-1 && o.stored==-1);
}
static void test_check(void)
{
    begin("check changes nothing and reuses the backup");
    CHECK(run("check",NULL,NULL)==0);
    CHECK(world.backups==1 && world.preflights==1 && world.dry_runs==0 && world.applies==0);
    CHECK(exists("dubfix-data/02-11-22-33-44-55/backup/backup.bin"));
    CHECK(run("check",NULL,NULL)==0 && world.backups==1 && world.preflights==2);
    begin("check reports no adapter");
    world.adapters=0; CHECK(run("check",NULL,NULL)==1 && world.backups==0);
    begin("check reports wrong hardware");
    world.wrong_hardware=1; CHECK(run("check",NULL,NULL)==1 && world.backups==0);
    CHECK(run("check","test0",NULL)==1 && world.backups==0);
    begin("check reports an unsupported layout");
    world.unsupported_layout=1; CHECK(run("check",NULL,NULL)==1 && world.preflights==0);
    CHECK(run("fix",NULL,"4455")==1 && world.backups==1 && world.applies==0);
    begin("a failed backup is set aside and retried");
    world.backup_fails=1; CHECK(run("check",NULL,NULL)==1 && world.plans==0);
    world.backup_fails=0; CHECK(run("check",NULL,NULL)==0 && world.backups==2);
    begin("two adapters need a name");
    world.adapters=2; CHECK(run("fix",NULL,"4455")==1 && world.backups==0 && world.applies==0);
    CHECK(run("check","test1",NULL)==0 && !strcmp(world.iface,"test1"));
    CHECK(exists("dubfix-data/02-11-22-33-44-56/backup/backup.bin"));
    CHECK(run("check","test9",NULL)==1);
}
static void test_fix(void)
{
    begin("fix writes once after the right confirmation");
    CHECK(run("fix",NULL,"44:55\n")==0);
    CHECK(world.dry_runs==1 && world.applies==1 && !strcmp(world.token,"SYNTHETIC-TOKEN"));
    CHECK(run("fix",NULL,"4455\n")==0 && world.applies==1 && world.dry_runs==1);
    begin("fix cancels on a wrong or empty confirmation");
    CHECK(run("fix",NULL,"yes\n")==1 && world.applies==0);
    CHECK(run("fix",NULL,"\n")==1 && world.applies==0);
    CHECK(run("fix",NULL,NULL)==1 && world.applies==0);
    CHECK(run("fix",NULL,"4456\n")==1 && world.applies==0 && world.dry_runs==4);
    begin("fix stops when the rehearsal fails");
    world.dry_run_fails=1; CHECK(run("fix",NULL,"4455\n")==1 && world.applies==0);
    begin("a write refused before programming may be retried");
    world.apply_mode=APPLY_REFUSED_EARLY; CHECK(run("fix",NULL,"4455\n")==1 && world.applies==1);
    world.apply_mode=APPLY_OK; CHECK(run("fix",NULL,"4455\n")==0 && world.applies==2);
    for (int mode=APPLY_UNCERTAIN;mode<=APPLY_KILLED;mode++) {
        begin("an uncertain write is never retried");
        world.apply_mode=mode; CHECK(run("fix",NULL,"4455\n")==1 && world.applies==1);
        world.apply_mode=APPLY_OK;
        CHECK(run("fix",NULL,"4455\n")==1 && world.applies==1 && world.dry_runs==1);
        CHECK(run("check",NULL,NULL)==0);
        world.stored=1; CHECK(run("fix",NULL,"4455\n")==0 && world.applies==1);
    }
}
static void test_verify(void)
{
    begin("verify needs the backup, then reports stored and active");
    CHECK(run("verify",NULL,NULL)==1 && world.verifies==0);
    CHECK(run("fix",NULL,"4455\n")==0);
    CHECK(run("verify",NULL,NULL)==1 && world.verifies==1);
    world.active=1; CHECK(run("verify",NULL,NULL)==0 && world.verifies==2);
    begin("usage errors run nothing");
    char *none[]={"dubfix",NULL},*unknown[]={"dubfix","list",NULL},*extra[]={"dubfix","fix","a","b",NULL};
    CHECK(dubfix_test_front_main(1,none)==2 && dubfix_test_front_main(2,unknown)==2 && dubfix_test_front_main(4,extra)==2);
    char *step[]={"dubfix","step","list",NULL};
    CHECK(dubfix_test_front_main(3,step)==99 && world.lists==0);
}
int main(void)
{
    run_step=fake_step;
    test_parsers(); test_check(); test_fix(); test_verify();
    printf("cli tests: %u assertions, %u failures\n",assertions,failures);
    return failures?1:0;
}
