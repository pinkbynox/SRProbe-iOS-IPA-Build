#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <errno.h>
#import <fcntl.h>
#import <spawn.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/syscall.h>
#import <unistd.h>

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

#ifndef VM_PROT_SLIDE
#define VM_PROT_SLIDE 0x20
#endif

struct shared_file_np_local {
    int      sf_fd;
    uint32_t sf_mappings_count;
    uint32_t sf_slide;
};

struct shared_file_mapping_slide_np_local {
    uint64_t sms_address;
    uint64_t sms_size;
    uint64_t sms_file_offset;
    uint64_t sms_slide_size;
    uint64_t sms_slide_start;
    int      sms_max_prot;
    int      sms_init_prot;
};

static NSMutableString *gLogs;

static void SRLog(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);

    NSString *full = [NSString stringWithFormat:@"[SR-PROBE] %@\n", line];
    NSLog(@"%@", full);

    if (!gLogs) {
        gLogs = [NSMutableString string];
    }

    [gLogs appendString:full];

    [[NSNotificationCenter defaultCenter] postNotificationName:@"SRProbeLogsUpdated"
                                                        object:nil];
}

static void log_errno(NSString *name, long ret) {
    int e = errno;
    SRLog(@"%@ ret=%ld errno=%d (%s)", name, ret, e, strerror(e));
}

static NSString *makeProbeFile(void) {
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"sr_probe_file.bin"];

    NSMutableData *data = [NSMutableData dataWithLength:0x4000];
    uint8_t *p = (uint8_t *)data.mutableBytes;
    memcpy(p, "SRPROBE", 7);

    BOOL ok = [data writeToFile:path atomically:YES];
    SRLog(@"makeProbeFile path=%@ ok=%d", path, ok ? 1 : 0);

    return path;
}

static void test_shared_region_check(void) {
    errno = 0;
    uint64_t start = 0;

    long ret = syscall(SYS_shared_region_check_np, &start);

    SRLog(@"shared_region_check_np syscall ret=%ld errno=%d (%s) start=0x%llx",
          ret, errno, strerror(errno), start);
}

static void test_shared_region_check_null(void) {
    errno = 0;

    long ret = syscall(SYS_shared_region_check_np, NULL);

    SRLog(@"shared_region_check_np NULL syscall ret=%ld errno=%d (%s)",
          ret, errno, strerror(errno));
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

    SRLog(@"probe file no_slide fd=%d errno=%d (%s)", fd, errno, strerror(errno));

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

    SRLog(@"probe file with_slide fd=%d errno=%d (%s)", fd, errno, strerror(errno));

    if (fd < 0) {
        log_errno(@"open probe file slide", -1);
        return;
    }

    void *slide = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);

    if (slide == MAP_FAILED) {
        log_errno(@"mmap slide", -1);
        close(fd);
        return;
    }

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

static void test_path_no_slide(NSString *path) {
    errno = 0;
    int fd = open(path.UTF8String, O_RDONLY);

    SRLog(@"open system path=%@ fd=%d errno=%d (%s)",
          path, fd, errno, strerror(errno));

    if (fd < 0) {
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

    log_errno([NSString stringWithFormat:@"syscall536 path_no_slide %@", path], ret);

    close(fd);
}

static void test_path_with_slide_benign(NSString *path) {
    errno = 0;
    int fd = open(path.UTF8String, O_RDONLY);

    SRLog(@"open system path with_slide=%@ fd=%d errno=%d (%s)",
          path, fd, errno, strerror(errno));

    if (fd < 0) {
        return;
    }

    void *slide = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);

    if (slide == MAP_FAILED) {
        log_errno(@"mmap system benign slide", -1);
        close(fd);
        return;
    }

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

    log_errno([NSString stringWithFormat:@"syscall536 path_with_slide_benign %@", path], ret);

    munmap(slide, 0x4000);
    close(fd);
}

static void test_system_paths(void) {
    NSArray<NSString *> *paths = @[
        @"/usr/lib/dyld",
        @"/System/Library/Frameworks/UIKit.framework/UIKit",
        @"/System/Library/Frameworks/Foundation.framework/Foundation",
        @"/System/Library/dyld/dyld_shared_cache_arm64e",
        @"/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
        @"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
        @"/private/preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
    ];

    for (NSString *path in paths) {
        test_path_no_slide(path);
    }

    for (NSString *path in paths) {
        test_path_with_slide_benign(path);
    }
}

static void runProbe(void) {
    SRLog(@"===== begin =====");
    SRLog(@"pid=%d", getpid());

    test_shared_region_check();
    test_syscall_empty();
    test_syscall_bad_fd_no_slide();
    test_syscall_container_file_no_slide();
    test_syscall_container_file_with_slide_flag_benign();

    test_system_paths();

    SRLog(@"===== end =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(strong, nonatomic) UIWindow *window;
@property(strong, nonatomic) UITextView *textView;
@end

@implementation AppDelegate

- (void)refreshLogs {
    self.textView.text = gLogs ?: @"";

    if (self.textView.text.length > 0) {
        NSRange bottom = NSMakeRange(self.textView.text.length - 1, 1);
        [self.textView scrollRangeToVisible:bottom];
    }
}

- (UIButton *)buttonWithTitle:(NSString *)title action:(SEL)action frame:(CGRect)frame {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.frame = frame;
    [button setTitle:title forState:UIControlStateNormal];
    button.backgroundColor = [UIColor colorWithWhite:0.90 alpha:1.0];
    button.layer.cornerRadius = 8;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)copyLogs {
    [UIPasteboard generalPasteboard].string = gLogs ?: @"";
    SRLog(@"logs copied to pasteboard");
}

- (void)shareLogs {
    NSString *logs = gLogs ?: @"";

    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[logs]
                                                                     applicationActivities:nil];

    [self.window.rootViewController presentViewController:vc animated:YES completion:nil];
}

- (void)rerunProbe {
    if (!gLogs) {
        gLogs = [NSMutableString string];
    }

    [gLogs setString:@""];
    [self refreshLogs];

    runProbe();
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    gLogs = [NSMutableString string];

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];

    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor whiteColor];

    CGFloat width = root.view.bounds.size.width;
    CGFloat height = root.view.bounds.size.height;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(16, 48, width - 32, 30)];
    title.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    title.text = @"SRProbe logs";
    title.font = [UIFont boldSystemFontOfSize:22];
    title.textColor = [UIColor blackColor];
    [root.view addSubview:title];

    CGFloat buttonY = 88;

    UIButton *copy = [self buttonWithTitle:@"Copy logs"
                                    action:@selector(copyLogs)
                                     frame:CGRectMake(16, buttonY, 105, 42)];

    UIButton *share = [self buttonWithTitle:@"Share logs"
                                     action:@selector(shareLogs)
                                      frame:CGRectMake(132, buttonY, 105, 42)];

    UIButton *rerun = [self buttonWithTitle:@"Run again"
                                     action:@selector(rerunProbe)
                                      frame:CGRectMake(248, buttonY, 105, 42)];

    [root.view addSubview:copy];
    [root.view addSubview:share];
    [root.view addSubview:rerun];

    self.textView = [[UITextView alloc] initWithFrame:CGRectMake(12, 145, width - 24, height - 160)];
    self.textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.textView.editable = NO;
    self.textView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.textView.textColor = [UIColor blackColor];
    self.textView.backgroundColor = [UIColor colorWithWhite:0.96 alpha:1.0];
    self.textView.layer.cornerRadius = 8;

    [root.view addSubview:self.textView];

    [[NSNotificationCenter defaultCenter] addObserverForName:@"SRProbeLogsUpdated"
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *note) {
        [self refreshLogs];
    }];

    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        runProbe();
    });

    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
