#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <signal.h>
#import <stdint.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/syscall.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

#ifndef SYS_shared_region_check_np
#define SYS_shared_region_check_np 294
#endif
#ifndef SYS_shared_region_map_and_slide_2_np
#define SYS_shared_region_map_and_slide_2_np 536
#endif

#ifndef VM_PROT_READ
#define VM_PROT_READ 0x01
#endif
#ifndef VM_PROT_WRITE
#define VM_PROT_WRITE 0x02
#endif
#ifndef VM_PROT_EXECUTE
#define VM_PROT_EXECUTE 0x04
#endif
#ifndef VM_PROT_COW
#define VM_PROT_COW 0x08
#endif
#ifndef VM_PROT_ZF
#define VM_PROT_ZF 0x10
#endif
#ifndef VM_PROT_SLIDE
#define VM_PROT_SLIDE 0x20
#endif
#ifndef VM_PROT_NOAUTH
#define VM_PROT_NOAUTH 0x40
#endif

typedef struct shared_file_np_local {
    int      sf_fd;
    uint32_t sf_mappings_count;
    uint32_t sf_slide;
} shared_file_np_local;

typedef struct shared_file_mapping_slide_np_local {
    uint64_t sms_address;
    uint64_t sms_size;
    uint64_t sms_file_offset;
    uint64_t sms_slide_size;
    uint64_t sms_slide_start;
    int      sms_max_prot;
    int      sms_init_prot;
} shared_file_mapping_slide_np_local;

static void install_signal_handlers(void) {
    signal(SIGSYS, [](int sig) {
        NSLog(@"[SR-PROBE] caught SIGSYS=%d", sig);
        _exit(128 + sig);
    });
    signal(SIGSEGV, [](int sig) {
        NSLog(@"[SR-PROBE] caught SIGSEGV=%d", sig);
        _exit(128 + sig);
    });
}

static void log_errno(NSString *name, long ret) {
    int e = errno;
    NSLog(@"[SR-PROBE] %@ ret=%ld errno=%d (%s)", name, ret, e, strerror(e));
}

static NSString *makeProbeFile(void) {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"sr_probe_file.bin"];
    NSMutableData *data = [NSMutableData dataWithLength:0x4000];
    uint8_t *p = (uint8_t *)data.mutableBytes;
    memcpy(p, "SRPROBE", 7);
    [data writeToFile:path atomically:YES];
    return path;
}

static void test_shared_region_check(void) {
    errno = 0;
    uint64_t start = 0;
    long ret = syscall(SYS_shared_region_check_np, &start);
    int e = errno;
    NSLog(@"[SR-PROBE] syscall294 shared_region_check_np ret=%ld errno=%d (%s) start=0x%llx",
          ret, e, strerror(e), start);
}

static void test_shared_region_check_null(void) {
    errno = 0;
    long ret = syscall(SYS_shared_region_check_np, NULL);
    log_errno(@"syscall294 shared_region_check_np(NULL)", ret);
}

static void test_syscall_empty(void) {
    errno = 0;
    long ret = syscall(SYS_shared_region_map_and_slide_2_np,
                       0, NULL,
                       0, NULL);
    log_errno(@"syscall536 empty", ret);
}

static void test_syscall_bad_fd_no_slide(void) {
    shared_file_np_local files[1] = {};
    shared_file_mapping_slide_np_local maps[1] = {};

    files[0].sf_fd = -1;
    files[0].sf_mappings_count = 1;
    files[0].sf_slide = 0;

    maps[0].sms_address = 0x180000000ULL;
    maps[0].sms_size = 0x4000;
    maps[0].sms_file_offset = 0;
    maps[0].sms_slide_size = 0;
    maps[0].sms_slide_start = 0;
    maps[0].sms_max_prot = VM_PROT_READ;
    maps[0].sms_init_prot = VM_PROT_READ;

    errno = 0;
    long ret = syscall(SYS_shared_region_map_and_slide_2_np,
                       1, files,
                       1, maps);
    log_errno(@"syscall536 bad_fd_no_slide", ret);
}

static void test_syscall_container_file_no_slide(void) {
    NSString *path = makeProbeFile();
    int fd = open(path.UTF8String, O_RDONLY);
    NSLog(@"[SR-PROBE] probe file=%@ fd=%d", path, fd);

    if (fd < 0) {
        log_errno(@"open probe file", -1);
        return;
    }

    shared_file_np_local files[1] = {};
    shared_file_mapping_slide_np_local maps[1] = {};

    files[0].sf_fd = fd;
    files[0].sf_mappings_count = 1;
    files[0].sf_slide = 0;

    maps[0].sms_address = 0x180000000ULL;
    maps[0].sms_size = 0x4000;
    maps[0].sms_file_offset = 0;
    maps[0].sms_slide_size = 0;
    maps[0].sms_slide_start = 0;
    maps[0].sms_max_prot = VM_PROT_READ;
    maps[0].sms_init_prot = VM_PROT_READ;

    errno = 0;
    long ret = syscall(SYS_shared_region_map_and_slide_2_np,
                       1, files,
                       1, maps);
    log_errno(@"syscall536 container_file_no_slide", ret);

    close(fd);
}

static void test_syscall_container_file_with_slide_flag_benign(void) {
    NSString *path = makeProbeFile();
    int fd = open(path.UTF8String, O_RDONLY);
    if (fd < 0) {
        log_errno(@"open probe file slide", -1);
        return;
    }

    void *slide = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (slide == MAP_FAILED) {
        log_errno(@"mmap benign slide", -1);
        close(fd);
        return;
    }

    // Benign/non-valid slide blob. It is intended to learn which gate rejects first.
    memset(slide, 0, 0x4000);

    shared_file_np_local files[1] = {};
    shared_file_mapping_slide_np_local maps[1] = {};

    files[0].sf_fd = fd;
    files[0].sf_mappings_count = 1;
    files[0].sf_slide = 0;

    maps[0].sms_address = 0x180000000ULL;
    maps[0].sms_size = 0x4000;
    maps[0].sms_file_offset = 0;
    maps[0].sms_slide_size = 0x4000;
    maps[0].sms_slide_start = (uint64_t)slide;
    maps[0].sms_max_prot = VM_PROT_READ | VM_PROT_SLIDE;
    maps[0].sms_init_prot = VM_PROT_READ | VM_PROT_SLIDE;

    errno = 0;
    long ret = syscall(SYS_shared_region_map_and_slide_2_np,
                       1, files,
                       1, maps);
    log_errno(@"syscall536 container_file_with_VM_PROT_SLIDE_benign", ret);

    munmap(slide, 0x4000);
    close(fd);
}

static void test_posix_spawn_env(void) {
    NSString *exe = [[NSBundle mainBundle] executablePath];

    char *argv[] = {
        (char *)exe.UTF8String,
        (char *)"--sr-child",
        NULL
    };

    char *envp[] = {
        (char *)"DYLD_SHARED_CACHE_DIR=/tmp/fake_dsc",
        (char *)"DYLD_SHARED_REGION=private",
        NULL
    };

    pid_t pid = 0;
    errno = 0;
    int ret = posix_spawn(&pid, exe.UTF8String, NULL, NULL, argv, envp);
    int e = errno;
    NSLog(@"[SR-PROBE] posix_spawn self ret=%d errno=%d (%s) pid=%d", ret, e, strerror(e), pid);

    if (ret == 0 && pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        NSLog(@"[SR-PROBE] posix_spawn child status=0x%x", status);
    }
}

static void runSharedRegionProbe(void) {
    install_signal_handlers();
    NSLog(@"[SR-PROBE] ===== begin =====");
    NSLog(@"[SR-PROBE] pid=%d exe=%@", getpid(), [[NSBundle mainBundle] executablePath]);

    test_shared_region_check();
    test_syscall_empty();
    test_syscall_bad_fd_no_slide();
    test_syscall_container_file_no_slide();
    test_syscall_container_file_with_slide_flag_benign();
    // Destructive to this task's shared-region association, so keep it late.
    test_shared_region_check_null();
    test_posix_spawn_env();

    NSLog(@"[SR-PROBE] ===== end =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectInset(self.window.bounds, 24, 120)];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = @"SRProbe running. Copy Xcode logs containing [SR-PROBE].";
    [vc.view addSubview:label];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    // Delay slightly so logs are easier to read after UI launch.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        runSharedRegionProbe();
    });
    return YES;
}
@end

int main(int argc, char * argv[]) {
    @autoreleasepool {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--sr-child") == 0) {
                NSLog(@"[SR-PROBE] child launched pid=%d", getpid());
                const char *dsc = getenv("DYLD_SHARED_CACHE_DIR");
                const char *dsr = getenv("DYLD_SHARED_REGION");
                NSLog(@"[SR-PROBE] child env DYLD_SHARED_CACHE_DIR=%s", dsc ? dsc : "<null>");
                NSLog(@"[SR-PROBE] child env DYLD_SHARED_REGION=%s", dsr ? dsr : "<null>");
                runSharedRegionProbe();
                return 0;
            }
        }
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
