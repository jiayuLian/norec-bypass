/* ---------------------------------------------------------------------------
 * NrcProbe — 阶梯式诊断 dylib
 *
 * 用途：NoRecBypass 注入后仍闪退时，用它把「崩在哪一级」逼出来。
 *
 * 和 NoRecBypass 的区别：
 *   · 每一级只做一件事，前后各打一行日志（[P0] ~ [P7]）
 *   · 日志同时写文件（fsync）并走 NSLog —— 电脑上跑 idevicesyslog
 *     或爱思助手/3uTools 的「实时日志」，崩溃前的最后一行会出现在屏幕上
 *
 * 判读方法（看日志最后停在哪一行）：
 *   只看得到 [P0]           → dylib 在 dyld 加载期就被拒了（签名/链接层问题）
 *   停在 [P1]               → 加载没问题，App 起来了，但 +5s 前就挂了
 *   停在 [P2] / 只看到 P2 前半 → hook UIScreen 本身有问题
 *   停在 [P3]               → hook NSNotificationCenter 有问题
 *   停在 [P4]               → hook NSURLSession 有问题
 *   停在 [P5]               → hook AVFoundation 有问题
 *   停在 [P6]               → 全量类清扫有问题
 *   看到 [P7]               → 30 秒内全程无崩溃，说明 hook 代码本身是干净的，
 *                              问题在别处（注入方式、别的插件、抖音自身反注入）
 * ------------------------------------------------------------------------- */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <os/lock.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>
#import <stdarg.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>

#define PROBE_VERSION "1.0.4-probe"

/* ============================== 日志 ============================== */

static char         gLogPath[1024] = {0};
static volatile int gNsLogOn       = 0;

static void NrcInitLogPath(void) {
    if (gLogPath[0] != '\0') {
        return;
    }
    const char *tmp = getenv("TMPDIR");
    if (tmp != NULL && tmp[0] == '/') {
        snprintf(gLogPath, sizeof(gLogPath), "%snorec_probe.log", tmp);
        return;
    }
    snprintf(gLogPath, sizeof(gLogPath), "/tmp/norec_probe.log");
}

static void NrcLogC(const char *fmt, ...) {
    NrcInitLogPath();

    char buf[4096];
    time_t now = time(NULL);
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    localtime_r(&now, &tmv);

    int head = snprintf(buf, sizeof(buf), "[%02d:%02d:%02d] ",
                        tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    if (head < 0 || head >= (int)sizeof(buf)) {
        head = 0;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + head, sizeof(buf) - (size_t)head, fmt, ap);
    va_end(ap);

    size_t len = strlen(buf);
    if (len + 2 > sizeof(buf)) {
        len = sizeof(buf) - 2;
    }
    buf[len]     = '\n';
    buf[len + 1] = '\0';
    len += 1;

    int fd = open(gLogPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, buf, len);
        (void)w;
        fsync(fd);
        close(fd);
    }

    if (gNsLogOn != 0) {
        NSString *line = [NSString stringWithUTF8String:buf];
        if (line != nil) {
            NSLog(@"[NRC-PROBE] %@", line);
        }
    }
}

static void NrcScheduleAfter(double seconds, BOOL onMain, void (^blk)(void)) {
    dispatch_queue_t q;
    if (onMain) {
        q = dispatch_get_main_queue();
    } else {
        q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(seconds * (double)NSEC_PER_SEC)),
                   q, blk);
}

/* ===================== 原始 IMP 登记表 ===================== */

#define NRC_ORIG_MAX 128

typedef struct {
    Class cls;
    SEL   sel;
    IMP   imp;
} NrcOrigSlot;

static NrcOrigSlot    gOrigs[NRC_ORIG_MAX];
static int            gOrigCount = 0;
static os_unfair_lock gOrigLock  = OS_UNFAIR_LOCK_INIT;

static void NrcOrigPut(Class cls, SEL sel, IMP imp) {
    if (cls == Nil || sel == NULL || imp == NULL) {
        return;
    }
    os_unfair_lock_lock(&gOrigLock);
    for (int i = 0; i < gOrigCount; i++) {
        if (gOrigs[i].cls == cls && gOrigs[i].sel == sel) {
            gOrigs[i].imp = imp;
            os_unfair_lock_unlock(&gOrigLock);
            return;
        }
    }
    if (gOrigCount < NRC_ORIG_MAX) {
        gOrigs[gOrigCount].cls = cls;
        gOrigs[gOrigCount].sel = sel;
        gOrigs[gOrigCount].imp = imp;
        gOrigCount++;
    }
    os_unfair_lock_unlock(&gOrigLock);
}

static IMP NrcOrigGet(id self, SEL sel) {
    if (self == nil || sel == NULL) {
        return NULL;
    }
    Class start = object_getClass(self);
    IMP   found = NULL;
    os_unfair_lock_lock(&gOrigLock);
    for (Class k = start; k != Nil && found == NULL; k = class_getSuperclass(k)) {
        for (int i = 0; i < gOrigCount; i++) {
            if (gOrigs[i].cls == k && gOrigs[i].sel == sel) {
                found = gOrigs[i].imp;
                break;
            }
        }
    }
    os_unfair_lock_unlock(&gOrigLock);
    return found;
}

/* ========================== hook 工具 ========================== */

static BOOL NrcClassDefines(Class cls, SEL sel) {
    BOOL found = NO;
    unsigned int n = 0;
    Method *ms = class_copyMethodList(cls, &n);
    if (ms != NULL) {
        for (unsigned int i = 0; i < n; i++) {
            if (method_getName(ms[i]) == sel) {
                found = YES;
                break;
            }
        }
        free(ms);
    }
    return found;
}

static BOOL NrcHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOld) {
    if (cls == Nil || sel == NULL || newImp == NULL) {
        return NO;
    }
    Method m = class_getInstanceMethod(cls, sel);
    if (m == NULL) {
        return NO;
    }
    IMP old = method_getImplementation(m);
    if (class_addMethod(cls, sel, newImp, method_getTypeEncoding(m))) {
        NrcOrigPut(cls, sel, old);
        if (outOld != NULL) {
            *outOld = old;
        }
        return YES;
    }
    Method own = class_getInstanceMethod(cls, sel);
    if (own == NULL) {
        return NO;
    }
    IMP prev = method_setImplementation(own, newImp);
    NrcOrigPut(cls, sel, prev);
    if (outOld != NULL) {
        *outOld = prev;
    }
    return YES;
}

static BOOL NrcHookClass(Class cls, SEL sel, IMP newImp, IMP *outOld) {
    if (cls == Nil || sel == NULL || newImp == NULL) {
        return NO;
    }
    Method m = class_getClassMethod(cls, sel);
    if (m == NULL) {
        return NO;
    }
    Class meta = object_getClass(cls);
    IMP old = method_getImplementation(m);
    if (class_addMethod(meta, sel, newImp, method_getTypeEncoding(m))) {
        NrcOrigPut(meta, sel, old);
        if (outOld != NULL) {
            *outOld = old;
        }
        return YES;
    }
    Method own = class_getClassMethod(cls, sel);
    if (own == NULL) {
        return NO;
    }
    IMP prev = method_setImplementation(own, newImp);
    NrcOrigPut(meta, sel, prev);
    if (outOld != NULL) {
        *outOld = prev;
    }
    return YES;
}

static int NrcHookCluster(NSString *needle, SEL sel, IMP newImp) {
    if (needle.length == 0 || sel == NULL || newImp == NULL) {
        return 0;
    }
    int hooked = 0;
    int count = objc_getClassList(NULL, 0);
    if (count > 0) {
        Class *list = (Class *)calloc((size_t)count, sizeof(Class));
        if (list != NULL) {
            objc_getClassList(list, count);
            for (int i = 0; i < count; i++) {
                Class c = list[i];
                const char *cn = class_getName(c);
                if (cn == NULL || strncmp(cn, "Nrc", 3) == 0) {
                    continue;
                }
                if (strstr(cn, needle.UTF8String) == NULL) {
                    continue;
                }
                if (!NrcClassDefines(c, sel)) {
                    continue;
                }
                if (NrcHookInstance(c, sel, newImp, NULL)) {
                    hooked++;
                    NrcLogC("        -[%s %s]", cn, sel_getName(sel));
                }
            }
            free(list);
        }
    }
    if (hooked == 0) {
        Class base = NSClassFromString(needle);
        if (base != Nil && NrcHookInstance(base, sel, newImp, NULL)) {
            hooked++;
            NrcLogC("        -[%s %s] (基类兜底)", needle.UTF8String, sel_getName(sel));
        }
    }
    return hooked;
}

/* ========================== 各级 hook ========================== */

static volatile int gCapturedCalls = 0;

static BOOL NrcIsCapturedFalse(id self, SEL _cmd) {
    int n = __sync_add_and_fetch(&gCapturedCalls, 1);
    if (n <= 10 || (n % 50) == 0) {
        NrcLogC("        [HIT] -[%s isCaptured] -> NO (第 %d 次)",
                object_getClassName(self), n);
    }
    return NO;
}

static BOOL NrcIsCaptureNotify(NSString *name) {
    if (name.length == 0) {
        return NO;
    }
    return [name isEqualToString:@"UIScreenCapturedDidChangeNotification"]
        || [name isEqualToString:@"UIScreenCaptureDidChangeNotification"];
}

static id NrcAddObsSel(id self, SEL _cmd, id observer, SEL sel, NSString *name, id object) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    if (NrcIsCaptureNotify(name)) {
        NrcLogC("        [BLOCK] addObserver:selector:name:object: %s", name.UTF8String);
        return nil;
    }
    return ((id (*)(id, SEL, id, SEL, NSString *, id))orig)(self, _cmd, observer, sel, name, object);
}

typedef void (^NrcNotifyBlock)(NSNotification *note);

static id NrcAddObsBlk(id self, SEL _cmd, NSString *name, id object,
                       NSOperationQueue *queue, NrcNotifyBlock block) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    if (NrcIsCaptureNotify(name)) {
        NrcLogC("        [BLOCK] addObserverForName:object:queue:usingBlock: %s", name.UTF8String);
        return nil;
    }
    return ((id (*)(id, SEL, NSString *, id, NSOperationQueue *, NrcNotifyBlock))orig)
        (self, _cmd, name, object, queue, block);
}

static volatile int gUrlSeen = 0;

static id NrcDtReq(id self, SEL _cmd, NSURLRequest *req) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    int n = __sync_add_and_fetch(&gUrlSeen, 1);
    if (n <= 12) {
        NrcLogC("        [REQ] %s %s", object_getClassName(self),
                req.URL.absoluteString.UTF8String);
    }
    return ((id (*)(id, SEL, NSURLRequest *))orig)(self, _cmd, req);
}

typedef void (^NrcDataBlock)(NSData *data, NSURLResponse *response, NSError *error);

static id NrcDtReqComp(id self, SEL _cmd, NSURLRequest *req, NrcDataBlock cb) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    int n = __sync_add_and_fetch(&gUrlSeen, 1);
    if (n <= 12) {
        NrcLogC("        [REQ] %s %s", object_getClassName(self),
                req.URL.absoluteString.UTF8String);
    }
    NrcDataBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        NrcLogC("        [RESP] %ld %luB %s", (long)[(NSHTTPURLResponse *)resp statusCode],
                (unsigned long)data.length, req.URL.absoluteString.UTF8String);
        if (cb != nil) {
            cb(data, resp, err);
        }
    };
    return ((id (*)(id, SEL, NSURLRequest *, NrcDataBlock))orig)(self, _cmd, req, wrapped);
}

static id NrcAssetInit(id self, SEL _cmd, NSURL *url, NSDictionary *opts) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("        [AV] AVURLAsset initWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *, NSDictionary *))orig)(self, _cmd, url, opts);
}

static id NrcItemInit(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("        [AV] AVPlayerItem initWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

/* ---- 简化版清扫：只报数，不真的改实现（诊断用，最保守）---- */
static void NrcScanCapturedAPIs(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return;
    }
    Class *list = (Class *)calloc((size_t)count, sizeof(Class));
    if (list == NULL) {
        return;
    }
    objc_getClassList(list, count);

    int hits = 0;
    for (int i = 0; i < count; i++) {
        Class c = list[i];
        const char *cn = class_getName(c);
        if (cn == NULL) {
            continue;
        }
        unsigned int mn = 0;
        Method *ms = class_copyMethodList(c, &mn);
        if (ms == NULL) {
            continue;
        }
        for (unsigned int j = 0; j < mn; j++) {
            const char *sn = sel_getName(method_getName(ms[j]));
            if (sn == NULL) {
                continue;
            }
            char low[192];
            size_t k = 0;
            for (; sn[k] != '\0' && k + 1 < sizeof(low); k++) {
                char ch = sn[k];
                low[k] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
            }
            low[k] = '\0';
            if (strstr(low, "captur") == NULL) {
                continue;
            }
            const char *enc = method_getTypeEncoding(ms[j]);
            if (enc == NULL || strlen(enc) != 3 || enc[1] != '@' || enc[2] != ':') {
                continue;
            }
            if (enc[0] != 'c' && enc[0] != 'B' && enc[0] != 'b') {
                continue;
            }
            if (hits < 25) {
                NrcLogC("        [SCAN] -[%s %s]", cn, sn);
            }
            hits++;
        }
        free(ms);
    }
    free(list);
    NrcLogC("        [SCAN] 共扫到 %d 个「返回 BOOL、无参、名字含 captur」的方法", hits);
}

/* ========================== 阶梯 ========================== */

__attribute__((constructor))
static void NrcProbeEntry(void) {
    NrcInitLogPath();
    NrcLogC("================================================================");
    NrcLogC("[P0] NrcProbe %s · pid=%d · prog=%s", PROBE_VERSION,
            (int)getpid(), getprogname());
    NrcLogC("[P0] dylib 已被 dyld 加载，constructor 执行完毕（此处未做任何 hook）");
    NrcLogC("[P0] 日志文件 %s", gLogPath);
    NrcLogC("================================================================");

    NrcScheduleAfter(2.0, YES, ^{
        gNsLogOn = 1;
        NrcLogC("[P1] +2s  App 已跑起来 2 秒，日志双写已开。如果你只看到 [P0] 就退出了，说明是加载层问题（签名/依赖）");
    });

    NrcScheduleAfter(5.0, YES, ^{
        NrcLogC("[P2] +5s  开始 hook UIScreen.isCaptured ...");
        @try {
            Class screen = NSClassFromString(@"UIScreen");
            if (screen != Nil) {
                BOOL a = NrcHookInstance(screen, NSSelectorFromString(@"isCaptured"),
                                         (IMP)NrcIsCapturedFalse, NULL);
                BOOL b = NrcHookInstance(screen, NSSelectorFromString(@"_isCaptured"),
                                         (IMP)NrcIsCapturedFalse, NULL);
                NrcLogC("        isCaptured=%s _isCaptured=%s",
                        a ? "OK" : "未找到", b ? "OK" : "不存在");
            } else {
                NrcLogC("        找不到 UIScreen");
            }
        } @catch (NSException *e) {
            NrcLogC("        异常: %s", e.reason != nil ? e.reason.UTF8String : "?");
        }
        NrcLogC("[P2] +5s  UIScreen hook 结束");
    });

    NrcScheduleAfter(9.0, YES, ^{
        NrcLogC("[P3] +9s  开始 hook NSNotificationCenter ...");
        @try {
            int n1 = NrcHookCluster(@"NSNotificationCenter", @selector(addObserver:selector:name:object:), (IMP)NrcAddObsSel);
            int n2 = NrcHookCluster(@"NSNotificationCenter", @selector(addObserverForName:object:queue:usingBlock:), (IMP)NrcAddObsBlk);
            NrcLogC("        命中 %d / %d 个类", n1, n2);
        } @catch (NSException *e) {
            NrcLogC("        异常: %s", e.reason != nil ? e.reason.UTF8String : "?");
        }
        NrcLogC("[P3] +9s  NSNotificationCenter hook 结束");
    });

    NrcScheduleAfter(13.0, YES, ^{
        NrcLogC("[P4] +13s 开始 hook NSURLSession ...");
        @try {
            int a = NrcHookCluster(@"URLSession", @selector(dataTaskWithRequest:completionHandler:), (IMP)NrcDtReqComp);
            int b = NrcHookCluster(@"URLSession", @selector(dataTaskWithRequest:), (IMP)NrcDtReq);
            int c = NrcHookCluster(@"URLSession", @selector(dataTaskWithURL:), (IMP)NrcDtReq);
            NrcLogC("        命中 %d / %d / %d 个类", a, b, c);
        } @catch (NSException *e) {
            NrcLogC("        异常: %s", e.reason != nil ? e.reason.UTF8String : "?");
        }
        NrcLogC("[P4] +13s NSURLSession hook 结束");
    });

    NrcScheduleAfter(18.0, YES, ^{
        NrcLogC("[P5] +18s 开始 hook AVFoundation ...");
        @try {
            Class asset = NSClassFromString(@"AVURLAsset");
            if (asset != Nil) {
                NrcHookInstance(asset, NSSelectorFromString(@"initWithURL:options:"), (IMP)NrcAssetInit, NULL);
            }
            Class item = NSClassFromString(@"AVPlayerItem");
            if (item != Nil) {
                NrcHookInstance(item, NSSelectorFromString(@"initWithURL:"), (IMP)NrcItemInit, NULL);
                NrcHookClass(item, NSSelectorFromString(@"playerItemWithURL:"), (IMP)NrcItemInit, NULL);
            }
            NrcLogC("        AVURLAsset=%d AVPlayerItem=%d", asset != Nil ? 1 : 0, item != Nil ? 1 : 0);
        } @catch (NSException *e) {
            NrcLogC("        异常: %s", e.reason != nil ? e.reason.UTF8String : "?");
        }
        NrcLogC("[P5] +18s AVFoundation hook 结束");
    });

    NrcScheduleAfter(24.0, NO, ^{
        NrcLogC("[P6] +24s 开始全量扫描 captur 相关方法（只统计，不改实现）...");
        @try {
            NrcScanCapturedAPIs();
        } @catch (NSException *e) {
            NrcLogC("        异常: %s", e.reason != nil ? e.reason.UTF8String : "?");
        }
        NrcLogC("[P6] +24s 全量扫描结束");
    });

    NrcScheduleAfter(30.0, YES, ^{
        NrcLogC("[P7] +30s 全部阶梯走完，30 秒内没有崩溃 ✓");
        NrcLogC("[P7] 结论：hook 代码本身是干净的，闪退原因不在这些 hook 上");
    });
}
