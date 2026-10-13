/* ---------------------------------------------------------------------------
 * NoRecBypass (NRC) — 抖音小程序「多来看点」录屏限制绕过 + 进程内流量取证
 *
 * 目标设备：iPhone · iOS 15.4.1 · TrollStore（非越狱）· 注入宿主 = 抖音
 * 版本：1.0.3（针对「注入后打开闪退」的加固版）
 *
 * ── 为什么不用 Logos ──────────────────────────────────────────────────────
 * Logos 的 %hook 会生成对 MSHookMessageEx / MSGetImageByName 的引用，于是 dylib
 * 多出一条加载命令 /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate。
 * TrollStore / TrollFools 只是签名劫持、不是越狱，设备上根本没有这个 framework，
 * dyld 会在加载期直接报 Library not loaded → 抖音启动即崩。
 * 所以这里全部手写 objc runtime swizzle，一个 Logos 指令都不用。
 *
 * ── v1.0.3 相对 v1.0.2 修了什么（重要）────────────────────────────────────
 *
 * [致命 BUG 修复] cluster hook 的原始 IMP 串线
 *   v1.0.2 里 NrcHookCluster 对「所有名字含 URLSession 的类」循环安装同一个
 *   hook 函数，却只把 outOld 写进一个全局变量 gOrigDtReqComp。循环结束时这个
 *   全局变量只剩「最后一个类」的原实现。运行时 __NSCFURLSession 的实例进来，
 *   却跳去执行 NSURLSession（另一个类）的实现 —— self/参数类型错位，直接崩。
 *   抖音启动阶段就会发网络请求，所以表现为「打开秒退」。
 *   v1.0.3 改成 per-class 原始实现登记表（NrcOrigPut / NrcOrigGet），
 *   hook 函数运行时用 object_getClass(self) 沿继承链查回「自己那一份」实现；
 *   查不到就安全兜底，绝不乱跳。
 *
 * [致命风险修复] dyld 加载期动 Objective-C runtime
 *   v1.0.2 把全量类清扫、几十个类的 swizzle、开 socket 服务全部塞在
 *   __attribute__((constructor)) 里同步执行。抖音有数万个类，在 dyld 持有加载锁
 *   期间调用 NSClassFromString / objc_getClassList / class_copyMethodList，极易
 *   触发 +initialize 重入死锁或被看门狗击杀（0x8badf00d）。
 *   v1.0.3 的 constructor 只做两件事：写一行日志、注册一个延迟任务。所有 hook
 *   都在启动完成之后（+2s / +6s / +14s）分三级安装，随时可定位崩在哪一级。
 *
 * [安全网] 启动自保护
 *   每次启动自增一个计数文件，连续崩溃 2 次就自动切「最小模式」（只做录屏绕过，
 *   不碰网络/清扫），保证你不会被卡在「一打开就退」的死循环里出不来。
 *
 * [可观测] 每一步都 fsync 落盘
 *   日志用纯 POSIX open/write/fsync，不用 NSLog、不用 ObjC。崩溃瞬间最后一行
 *   日志必定已经在磁盘上 → 直接把崩溃点定位到具体阶段。
 *
 * ── 三件事 ────────────────────────────────────────────────────────────────
 * 1) 录屏检测绕过（核心，Stage1）
 *    抖音小程序用 -[UIScreen isCaptured] 判断是否正在录屏；为真就把播放面涂黑
 *    并弹「付费内容仅支持在小程序内观看」。把该方法恒返回 NO，并把
 *    UIScreenCapturedDidChangeNotification 的观察者注册一并拦掉（双保险）。
 *
 * 2) 进程内流量取证（Stage2）
 *    小游戏/小程序的视频走抖音自研 TTNet 直连 socket，不理会系统 HTTP 代理，
 *    且做证书固定 —— 所以抓包抓不到。但业务接口是走系统网络栈的（抓包时能看到
 *    它们连到代理并握手失败，正好说明它们走的是 NSURLSession）。进程内 hook
 *    NSURLSession / AVFoundation，读到的是解密后的明文，证书固定完全不起作用。
 *
 * 3) 把日志取回来
 *    抖音容器里的文件在非越狱设备上不好取，所以内置一个极小的 HTTP 服务，
 *    监听 0.0.0.0:8899。用同一 WiFi 下的电脑浏览器打开 http://<手机IP>:8899/
 *    就能看到完整日志（抖音保持前台即可）。
 *
 * ── 版本锚点：改代码请同步改 NRC_VERSION，产物里靠它认版本 ────────────────
 * ------------------------------------------------------------------------- */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#import <os/lock.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>
#import <stdarg.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>
#import <errno.h>

#define NRC_VERSION        @"1.0.4"
#define NRC_PORT           8899
#define NRC_URL_MAX        5000
#define NRC_BODY_MAX       200

/* 启动自保护：连续崩溃这么多次就切最小模式 */
#define NRC_CRASH_MINIMAL  2
/* 平稳运行满这么久，认为本次启动健康，清零崩溃计数 */
#define NRC_HEALTHY_SECOND 15.0

/* 分级安装的时间点（秒，相对 constructor 执行时刻） */
#define NRC_T_STAGE1       2.0    /* 录屏绕过 —— 最小可用集 */
#define NRC_T_STAGE2       6.0    /* 网络 / 媒体取证 */
#define NRC_T_STAGE3       14.0   /* 全量 API 清扫 */

/* ============================== 前向声明 ============================== */
static void      NrcInitLogPath(void);
static void      NrcLogC(const char *fmt, ...);
static void      NrcOrigPut(Class cls, SEL sel, IMP imp);
static IMP       NrcOrigGet(id self, SEL sel);
static BOOL      NrcHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOld);
static BOOL      NrcHookClass(Class cls, SEL sel, IMP newImp, IMP *outOld);
static BOOL      NrcClassDefines(Class cls, SEL sel);
static int       NrcHookCluster(NSString *needle, SEL sel, IMP newImp);
static void      NrcHookClusterOnce(NSString *needle, NSString *label, SEL sel, IMP newImp);
static void      NrcSweepCapturedAPIs(void);
static void      NrcStartHttpServer(void);
static void      NrcStartMaintenance(void);
static void      NrcScheduleAfter(double seconds, BOOL onMain, void (^blk)(void));
static void      NrcNoteRequest(NSURLRequest *req);
static void      NrcNoteResponse(NSURLRequest *req, NSURLResponse *resp, NSData *data);

/* ====================== 日志（纯 POSIX，零 ObjC）======================
 * constructor 跑在 dyld 加载期，这时候能少碰 ObjC 就少碰。日志走裸文件描述符，
 * 每行写完整即 fsync —— 崩溃瞬间最后一行日志必然已落盘，等于一个断点记录器。
 * ==================================================================== */

static char gLogPath[1024] = {0};

/* 日志双写开关：加 App 起来之后才打开（+2s）。
   constructor 跑在 dyld 加载期，那会儿连一行 ObjC 都不能碰，所以只写文件；
   到了 Stage1，同一行内容再走一遍 NSLog —— 这样电脑上跑 idevicesyslog
   （或爱思助手/3uTools 的「实时日志」）就能同步看到。
   进程即使随后崩掉，崩溃前的最后一行也已经打在电脑屏幕上了。 */
static volatile int gNsLogOn = 0;

static void NrcInitLogPath(void) {
    if (gLogPath[0] != '\0') {
        return;
    }
    /* 沙盒 App 一定拿得到 TMPDIR（结尾自带斜杠），全程不用 NSString */
    const char *tmp = getenv("TMPDIR");
    if (tmp != NULL && tmp[0] == '/') {
        snprintf(gLogPath, sizeof(gLogPath), "%snorec.log", tmp);
        return;
    }
    snprintf(gLogPath, sizeof(gLogPath), "/tmp/norec.log");
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
        fsync(fd);              /* 关键：崩溃前最后一行必须已在磁盘上 */
        close(fd);
    }

    /* 双写：+2s 之后同一行也丢给 NSLog，电脑上的实时日志就能看到 */
    if (gNsLogOn != 0) {
        NSString *line = [NSString stringWithUTF8String:buf];
        if (line != nil) {
            NSLog(@"[NRC] %@", line);
        }
    }
}

/* ========================= 启动自保护 =========================
 * 每次启动把 nrс_boot 计数 +1；平稳跑满 NRC_HEALTHY_SECOND 后清零。
 * 计数 >= NRC_CRASH_MINIMAL 说明上一次（或连续两次）启动都没活到 15 秒，
 * 那就只装最小集，保证抖音一定能进去。
 * ============================================================ */

static int  gCrashCount  = 0;
static BOOL gMinimalMode = NO;

static void NrcBootCounterPath(char *out, size_t cap) {
    const char *tmp = getenv("TMPDIR");
    if (tmp != NULL && tmp[0] == '/') {
        snprintf(out, cap, "%snrc_boot", tmp);
    } else {
        snprintf(out, cap, "/tmp/nrc_boot");
    }
}

static void NrcBumpCrashCount(void) {
    char p[1024];
    NrcBootCounterPath(p, sizeof(p));

    int v = 0;
    FILE *rf = fopen(p, "r");
    if (rf != NULL) {
        if (fscanf(rf, "%d", &v) != 1) {
            v = 0;
        }
        fclose(rf);
    }
    v++;
    gCrashCount = v;

    FILE *wf = fopen(p, "w");
    if (wf != NULL) {
        fprintf(wf, "%d", v);
        fclose(wf);
    }
}

static void NrcClearCrashCountLater(void) {
    NrcScheduleAfter(NRC_HEALTHY_SECOND, NO, ^{
        char p[1024];
        NrcBootCounterPath(p, sizeof(p));
        FILE *wf = fopen(p, "w");
        if (wf != NULL) {
            fprintf(wf, "0");
            fclose(wf);
        }
        NrcLogC("[GUARD] 已平稳运行 %.0f 秒，崩溃计数清零（本次启动健康）",
                NRC_HEALTHY_SECOND);
    });
}

/* ============ 原始 IMP 登记表（v1.0.3 的核心修复）============
 * 每个被 hook 的「类 + 选择子」单独登记它自己的原实现。运行时用
 * object_getClass(self) 沿继承链往上找，拿到的永远是「自己那一份」，
 * 绝不会串到另一个类的实现上。
 * ========================================================== */

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
    /* 沿继承链查：self 可能是「被 hook 的那个类的子类」 */
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

/* ============================== 调度 ============================== */

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

/* ============================== swizzle ============================== */

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

/* class_addMethod 成功 = 该类本来没有(继承来的)，我们只在本类加覆盖，父类不受影响；
   否则该类自己有实现，直接原地换 IMP。这样绝不会误改父类方法。
   无论走哪条分支，都把「该类原本会执行到的那份实现」登记进 NrcOrigPut。 */
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

/* NSURLSession 是 class cluster：真正实现挂在 __NSCFURLSession 这类具体类上，
   只 swizzle 抽象基类是拦不到的。所以按名字枚举，只 hook「自己直接定义了该方法」
   的类（避免重复 hook 与 IMP 串线）。一个都没命中时再退回 hook 基类。 */
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
                    NrcLogC("[HOOK] -[%s %s]", cn, sel_getName(sel));
                }
            }
            free(list);
        }
    }
    if (hooked == 0) {
        Class base = NSClassFromString(needle);
        if (base != Nil && NrcHookInstance(base, sel, newImp, NULL)) {
            hooked++;
            NrcLogC("[HOOK] -[%s %s] (基类兜底)", needle.UTF8String, sel_getName(sel));
        }
    }
    return hooked;
}

static void NrcHookClusterOnce(NSString *needle, NSString *label, SEL sel, IMP newImp) {
    @try {
        int n = NrcHookCluster(needle, sel, newImp);
        NrcLogC("[HOOK] %s -> %d 个类", label.UTF8String, n);
    } @catch (NSException *e) {
        NrcLogC("[ERR] hook %s 异常: %s", label.UTF8String,
                e.reason != nil ? e.reason.UTF8String : "?");
    }
}

/* ========================= 1. 录屏检测绕过 ========================= */

static volatile int gCapturedCalls = 0;

static BOOL NrcIsCapturedFalse(id self, SEL _cmd) {
    int n = __sync_add_and_fetch(&gCapturedCalls, 1);
    if (n <= 30 || (n % 50) == 0) {
        NrcLogC("[HIT] -[%s isCaptured] -> NO  (第 %d 次)",
                object_getClassName(self), n);
    }
    return NO;
}

static BOOL NrcIsCapturedUnderscoreFalse(id self, SEL _cmd) {
    NrcLogC("[HIT] -[%s _isCaptured] -> NO", object_getClassName(self));
    return NO;
}

/* 有些实现是「收到 UIScreenCapturedDidChangeNotification 就无脑涂黑」，
   未必回头再查 isCaptured。所以把这个通知的观察者注册直接拦掉。 */
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
        NrcLogC("[BLOCK] addObserver:selector:name:object: for %s", name.UTF8String);
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
        NrcLogC("[BLOCK] addObserverForName:object:queue:usingBlock: for %s", name.UTF8String);
        return nil;
    }
    return ((id (*)(id, SEL, NSString *, id, NSOperationQueue *, NrcNotifyBlock))orig)
        (self, _cmd, name, object, queue, block);
}

/* ---- 通用「捕获检测」清扫 --------------------------------------------------
 * UIScreen 是官方入口，但各家普遍会再包一层私有实现：_isCaptured、
 * isScreenCaptured、isBeingCaptured… 甚至是自己写的 wrapper 类。
 * 只 hook UIScreen 一旦漏掉那层包装，画面照样被涂黑。
 *
 * 这里对全量已加载类做清扫：凡是「返回 BOOL、无参、名字形如
 * is*captur(e|ed|ing)」的方法，一律恒返回 NO。
 * 名字过滤写得很窄（"captur" 之后只允许空 / e / ed / ing），免得误伤
 * isCaptureSessionSupported 这类无关方法。
 * ------------------------------------------------------------------------- */

static int gSweepGens  = 0;
static int gSweepTotal = 0;
static volatile int gSweepHits = 0;

/* 清扫是「名字猜语义」，风险最高，所以限制单轮最多改这么多个方法，
   宁可漏也不要因为一个大范围误伤把 App 搞挂。 */
#define NRC_SWEEP_PER_RUN 16

static void NrcLowerCopy(const char *src, char *dst, size_t cap) {
    if (dst == NULL || cap == 0) {
        return;
    }
    size_t i = 0;
    if (src != NULL) {
        for (; src[i] != '\0' && i + 1 < cap; i++) {
            char ch = src[i];
            dst[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        }
    }
    dst[i] = '\0';
}

static BOOL NrcSelLooksLikeCapturedCheck(const char *selName, const char *clsName) {
    if (selName == NULL || clsName == NULL) {
        return NO;
    }
    char low[192];
    NrcLowerCopy(selName, low, sizeof(low));

    const char *hit = strstr(low, "captur");
    if (hit != NULL) {
        const char *tail = hit + 6;              /* "captur" 之后的部分 */
        if (tail[0] == '\0') {
            return YES;                          /* isCapture / _isCapture */
        }
        if (tail[0] == 'e') {
            if (tail[1] == '\0') {
                return YES;                      /* isCapture */
            }
            if (strcmp(tail + 1, "d") == 0) {
                return YES;                      /* isCaptured */
            }
            if (strcmp(tail + 1, "dby") == 0) {
                return YES;                      /* isCapturedBy… */
            }
        }
        if (tail[0] == 'i' && strcmp(tail + 1, "ng") == 0) {
            return YES;                          /* isCapturing */
        }
        return NO;
    }

    /* Screen* 类上的 is*record* 一并覆盖（私有录屏 API 常挂在这里） */
    char lcls[192];
    NrcLowerCopy(clsName, lcls, sizeof(lcls));
    if (strstr(lcls, "screen") != NULL && strstr(low, "record") != NULL) {
        return YES;
    }
    return NO;
}

static BOOL NrcFalseSweep(id self, SEL _cmd) {
    int n = __sync_add_and_fetch(&gSweepHits, 1);
    if (n <= 40 || (n % 100) == 0) {
        NrcLogC("[HIT] -[%s %s] -> NO (sweep 第 %d 次)",
                object_getClassName(self), sel_getName(_cmd), n);
    }
    return NO;
}

static void NrcSweepCapturedAPIs(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return;
    }
    Class *list = (Class *)calloc((size_t)count, sizeof(Class));
    if (list == NULL) {
        return;
    }
    objc_getClassList(list, count);

    int hooked = 0;
    for (int i = 0; i < count && hooked < NRC_SWEEP_PER_RUN; i++) {
        Class c = list[i];
        const char *cn = class_getName(c);
        if (cn == NULL || strncmp(cn, "Nrc", 3) == 0) {
            continue;                            /* 别扫自己 */
        }
        unsigned int mn = 0;
        Method *ms = class_copyMethodList(c, &mn);
        if (ms == NULL) {
            continue;
        }
        for (unsigned int j = 0; j < mn && hooked < NRC_SWEEP_PER_RUN; j++) {
            SEL s = method_getName(ms[j]);
            const char *sn = sel_getName(s);
            if (sn == NULL || !NrcSelLooksLikeCapturedCheck(sn, cn)) {
                continue;
            }
            /* 必须是「返回 BOOL、0 个参数」：类型编码形如 c@: / B@: / b@: */
            const char *enc = method_getTypeEncoding(ms[j]);
            if (enc == NULL || strlen(enc) != 3 || enc[1] != '@' || enc[2] != ':') {
                continue;
            }
            if (enc[0] != 'c' && enc[0] != 'B' && enc[0] != 'b') {
                continue;
            }
            if (NrcHookInstance(c, s, (IMP)NrcFalseSweep, NULL)) {
                hooked++;
                NrcLogC("[SWEEP] -[%s %s] -> NO", cn, sn);
            }
        }
        free(ms);
    }
    free(list);

    gSweepGens++;
    gSweepTotal += hooked;
    NrcLogC("[SWEEP] 第 %d 轮：本轮覆盖 %d 个方法，累计 %d",
            gSweepGens, hooked, gSweepTotal);
}

/* 抖音有反注入逻辑，可能把自己的实现换回去；所以定期重申一遍。 */
static void NrcReassertCaptureHooks(void) {
    Class screen = NSClassFromString(@"UIScreen");
    if (screen == Nil) {
        return;
    }
    NrcHookInstance(screen, NSSelectorFromString(@"isCaptured"),  (IMP)NrcIsCapturedFalse, NULL);
    NrcHookInstance(screen, NSSelectorFromString(@"_isCaptured"), (IMP)NrcIsCapturedUnderscoreFalse, NULL);
}

static dispatch_source_t gMaintTimer = NULL;
static int               gMaintTick  = 0;

static void NrcStartMaintenance(void) {
    if (gMaintTimer != NULL) {
        return;
    }
    @try {
        dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                     dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
        if (t == NULL) {
            NrcLogC("[HOOK] 维护定时器创建失败（不影响其他功能）");
            return;
        }
        dispatch_source_set_timer(t,
                                  dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8ull * NSEC_PER_SEC)),
                                  (uint64_t)(5ull * NSEC_PER_SEC),
                                  (uint64_t)(500ull * NSEC_PER_MSEC));
        dispatch_source_set_event_handler(t, ^{
            gMaintTick++;
            NrcReassertCaptureHooks();
            if (gMaintTick == 2 || gMaintTick == 6 || gMaintTick == 18 || gMaintTick == 60) {
                NrcSweepCapturedAPIs();
            }
        });
        gMaintTimer = t;
        dispatch_resume(t);
        NrcLogC("[HOOK] 维护定时器已启动：每 5s 重申 isCaptured=NO，并在第 10/30/90/300s 重扫");
    } @catch (NSException *e) {
        NrcLogC("[ERR] 维护定时器异常: %s",
                e.reason != nil ? e.reason.UTF8String : "?");
    }
}

/* ========================= 2. 进程内流量取证 ========================= */

static volatile int gUrlCount  = 0;
static volatile int gBodyCount = 0;

static void NrcNoteRequest(NSURLRequest *req) {
    NSString *u = req.URL.absoluteString;
    if (u.length == 0 || [u hasPrefix:@"data:"]) {
        return;
    }
    BOOL hot = ([u containsString:@"lizhibj"] || [u containsString:@"duolai"]
                || [u containsString:@".m3u8"] || [u containsString:@".mp4"]
                || [u containsString:@"video"] || [u containsString:@"play"]);
    if (!hot && gUrlCount >= NRC_URL_MAX) {
        return;
    }
    gUrlCount++;
    NSString *shown = u.length > 600 ? [u substringToIndex:600] : u;
    NSString *method = req.HTTPMethod.length > 0 ? req.HTTPMethod : @"GET";
    NrcLogC("[REQ] %s %s", method.UTF8String, shown.UTF8String);
}

static void NrcNoteResponse(NSURLRequest *req, NSURLResponse *resp, NSData *data) {
    NSString *u = req.URL.absoluteString;
    NSInteger code = 0;
    if ([resp respondsToSelector:@selector(statusCode)]) {
        code = (NSInteger)[(NSHTTPURLResponse *)resp statusCode];
    }
    NSString *mime = resp.MIMEType != nil ? resp.MIMEType : @"?";
    NrcLogC("[RESP] %ld %luB %s %s", (long)code, (unsigned long)data.length,
            mime.UTF8String, u.UTF8String);

    /* 最终落地 URL 与原始 URL 不同 = 发生过重定向。m3u8/mp4 常常被 302 到带签名的
       CDN 地址，这条日志往往就是我们要的「真播放地址」。 */
    NSString *finalUrl = resp.URL.absoluteString;
    if (finalUrl.length > 0 && ![finalUrl isEqualToString:u]) {
        NrcLogC("[REDIR] %s",
                (finalUrl.length > 900 ? [finalUrl substringToIndex:900] : finalUrl).UTF8String);
    }

    if (data == nil || data.length == 0 || data.length > 524288 || gBodyCount >= NRC_BODY_MAX) {
        return;
    }
    NSString *lm = mime.lowercaseString;
    BOOL textual = ([lm containsString:@"json"] || [lm containsString:@"text"]
                    || [lm containsString:@"javascript"] || [lm containsString:@"xml"]);
    if (!textual) {
        return;
    }
    NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (body == nil) {
        body = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    }
    if (body.length == 0) {
        return;
    }
    gBodyCount++;
    if (body.length > 4000) {
        body = [body substringToIndex:4000];
    }
    NrcLogC("[BODY #%d] %s\n%s", gBodyCount, u.UTF8String, body.UTF8String);
}

typedef void (^NrcDataBlock)(NSData *data, NSURLResponse *response, NSError *error);

static id NrcDtReqComp(id self, SEL _cmd, NSURLRequest *req, NrcDataBlock cb) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NrcNoteRequest(req);
    NrcDataBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        NrcNoteResponse(req, resp, data);
        if (cb != nil) {
            cb(data, resp, err);
        }
    };
    return ((id (*)(id, SEL, NSURLRequest *, NrcDataBlock))orig)(self, _cmd, req, wrapped);
}

static id NrcDtUrlComp(id self, SEL _cmd, NSURL *url, NrcDataBlock cb) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NSURLRequest *req = url != nil ? [NSURLRequest requestWithURL:url] : nil;
    if (req != nil) {
        NrcNoteRequest(req);
    }
    NrcDataBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (req != nil) {
            NrcNoteResponse(req, resp, data);
        }
        if (cb != nil) {
            cb(data, resp, err);
        }
    };
    return ((id (*)(id, SEL, NSURL *, NrcDataBlock))orig)(self, _cmd, url, wrapped);
}

static id NrcDtReq(id self, SEL _cmd, NSURLRequest *req) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NrcNoteRequest(req);
    return ((id (*)(id, SEL, NSURLRequest *))orig)(self, _cmd, req);
}

static id NrcDtUrl(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NSURLRequest *req = url != nil ? [NSURLRequest requestWithURL:url] : nil;
    if (req != nil) {
        NrcNoteRequest(req);
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

/* downloadTask 也要记：有些播放器先把 m3u8 落到沙盒再喂给 AVPlayer。 */
static id NrcDlReq(id self, SEL _cmd, NSURLRequest *req) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NrcNoteRequest(req);
    return ((id (*)(id, SEL, NSURLRequest *))orig)(self, _cmd, req);
}

static id NrcDlUrl(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (orig == NULL) {
        return nil;
    }
    NSURLRequest *req = url != nil ? [NSURLRequest requestWithURL:url] : nil;
    if (req != nil) {
        NrcNoteRequest(req);
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

/* AVFoundation：抖音小程序播放器若走 AVPlayer，这里能直接拿到媒体地址。
   用 NSClassFromString 而不是 import，避免多链一个 framework。 */
static id NrcAssetInit(id self, SEL _cmd, NSURL *url, NSDictionary *opts) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("[AV] AVURLAsset initWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *, NSDictionary *))orig)(self, _cmd, url, opts);
}

static id NrcItemInit(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("[AV] AVPlayerItem initWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

static id NrcItemCls(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("[AV] AVPlayerItem playerItemWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

static id NrcPlayerInit(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("[AV] AVPlayer initWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

static id NrcPlayerCls(id self, SEL _cmd, NSURL *url) {
    IMP orig = NrcOrigGet(self, _cmd);
    if (url.absoluteString.length > 0) {
        NrcLogC("[AV] AVPlayer playerWithURL: %s", url.absoluteString.UTF8String);
    }
    if (orig == NULL) {
        return nil;
    }
    return ((id (*)(id, SEL, NSURL *))orig)(self, _cmd, url);
}

/* ========================= 3. 把日志取回来 ========================= */

static NSString *NrcWiFiAddress(void) {
    NSString *addr = nil;
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0 || ifa == NULL) {
        return nil;
    }
    for (struct ifaddrs *cur = ifa; cur != NULL; cur = cur->ifa_next) {
        if (cur->ifa_addr == NULL || cur->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        NSString *nm = [NSString stringWithUTF8String:cur->ifa_name];
        if (![nm isEqualToString:@"en0"]) {
            continue;
        }
        char host[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in *sin = (struct sockaddr_in *)cur->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host)) != NULL) {
            addr = [NSString stringWithUTF8String:host];
        }
    }
    freeifaddrs(ifa);
    return addr;
}

static void NrcSendAll(int cfd, const void *data, size_t len) {
    const char *p = (const char *)data;
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(cfd, p + off, len - off, 0);
        if (w <= 0) {
            return;
        }
        off += (size_t)w;
    }
}

static void NrcServeClient(int cfd) {
    char buf[2048];
    ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        return;
    }
    buf[n] = '\0';

    char path[512];
    path[0] = '\0';
    if (sscanf(buf, "GET %511s", path) != 1) {
        strncpy(path, "/", sizeof(path) - 1);
    }
    NrcLogC("[HTTP] %s", path);

    NSString *logPath = [NSString stringWithUTF8String:gLogPath];
    NSData *body = nil;
    NSString *ctype = @"text/plain; charset=utf-8";

    if (strcmp(path, "/") == 0 || strncmp(path, "/norec.log", 10) == 0) {
        body = [NSData dataWithContentsOfFile:logPath];
        if (body == nil) {
            body = [@"(日志还没生成或读不到)" dataUsingEncoding:NSUTF8StringEncoding];
        }
        if (body.length > 2097152) {
            body = [body subdataWithRange:NSMakeRange(body.length - 2097152, 2097152)];
        }
    } else {
        NSString *page = [NSString stringWithFormat:
            @"<!doctype html><meta charset=utf-8><title>NRC</title>"
            @"<style>body{font:16px -apple-system;margin:24px;line-height:1.7}"
            @"code{background:#f2f2f7;padding:2px 6px;border-radius:4px}</style>"
            @"<h2>NoRecBypass %@</h2>"
            @"<p>宿主进程：<code>%@</code>　崩溃计数：<code>%d</code>　最小模式：<code>%@</code></p>"
            @"<p>日志文件：<code>%@</code>（%lu 字节）</p>"
            @"<p><a href=\"/norec.log\">查看日志</a></p>"
            @"<p>先在抖音里播一集，再回来看这里。</p>",
            NRC_VERSION,
            NSProcessInfo.processInfo.processName,
            gCrashCount,
            gMinimalMode ? @"是" : @"否",
            logPath,
            (unsigned long)[[NSData dataWithContentsOfFile:logPath] length]];
        body = [page dataUsingEncoding:NSUTF8StringEncoding];
        ctype = @"text/html; charset=utf-8";
    }

    NSString *head = [NSString stringWithFormat:
        @"HTTP/1.1 200 OK\r\nContent-Type: %@\r\nContent-Length: %lu\r\n"
        @"Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        ctype, (unsigned long)body.length];
    NrcSendAll(cfd, head.UTF8String, strlen(head.UTF8String));
    if (body.length > 0) {
        NrcSendAll(cfd, body.bytes, (size_t)body.length);
    }
}

static void NrcServerLoop(void) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        NrcLogC("[HTTP] socket 创建失败 errno=%d", errno);
        return;
    }
    int on = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(NRC_PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sfd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        NrcLogC("[HTTP] bind %d 失败 errno=%d（不影响 hook）", NRC_PORT, errno);
        close(sfd);
        return;
    }
    if (listen(sfd, 16) != 0) {
        NrcLogC("[HTTP] listen 失败 errno=%d", errno);
        close(sfd);
        return;
    }
    NSString *ip = NrcWiFiAddress();
    NrcLogC("[HTTP] 已监听 0.0.0.0:%d —— 电脑浏览器打开 http://%s:%d/ 读日志",
            NRC_PORT, ip.length > 0 ? ip.UTF8String : "<手机IP>", NRC_PORT);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            continue;
        }
        @try {
            NrcServeClient(cfd);
        } @catch (NSException *e) {
            NrcLogC("[ERR] HTTP 服务异常: %s",
                    e.reason != nil ? e.reason.UTF8String : "?");
        }
        close(cfd);
    }
}

static void NrcStartHttpServer(void) {
    NrcScheduleAfter(NRC_T_STAGE1 + 1.0, NO, ^{
        @try {
            NrcServerLoop();
        } @catch (NSException *e) {
            NrcLogC("[ERR] HTTP 服务启动异常: %s",
                    e.reason != nil ? e.reason.UTF8String : "?");
        }
    });
}

/* ========================= 分级安装 =========================
 * 每一级都在日志里留首尾两行，崩溃时最后一行就是崩点。
 * ========================================================== */

static void NrcStage1(void) {
    gNsLogOn = 1;   /* App 已经起来了，从这里开始日志双写走 NSLog，电脑实时可见 */
    NrcLogC("[STAGE1] >>> 开始：录屏检测绕过（最小可用集）");

    @try {
        Class screen = NSClassFromString(@"UIScreen");
        if (screen != Nil) {
            BOOL a = NrcHookInstance(screen, NSSelectorFromString(@"isCaptured"),
                                     (IMP)NrcIsCapturedFalse, NULL);
            BOOL b = NrcHookInstance(screen, NSSelectorFromString(@"_isCaptured"),
                                     (IMP)NrcIsCapturedUnderscoreFalse, NULL);
            NrcLogC("[STAGE1] -[UIScreen isCaptured]  %s", a ? "OK" : "未找到");
            NrcLogC("[STAGE1] -[UIScreen _isCaptured] %s", b ? "OK" : "不存在(跳过)");
        } else {
            NrcLogC("[STAGE1] 找不到 UIScreen");
        }
    } @catch (NSException *e) {
        NrcLogC("[ERR] Stage1 UIScreen 异常: %s",
                e.reason != nil ? e.reason.UTF8String : "?");
    }

    NrcHookClusterOnce(@"NSNotificationCenter", @"通知拦截 addObserver:selector:name:object:",
                       @selector(addObserver:selector:name:object:), (IMP)NrcAddObsSel);
    NrcHookClusterOnce(@"NSNotificationCenter", @"通知拦截 addObserverForName:object:queue:usingBlock:",
                       @selector(addObserverForName:object:queue:usingBlock:), (IMP)NrcAddObsBlk);

    NrcStartHttpServer();
    NrcStartMaintenance();

    NrcLogC("[STAGE1] <<< 完成");
}

static void NrcStage2(void) {
    NrcLogC("[STAGE2] >>> 开始：网络 / 媒体取证");

    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithRequest:completionHandler:",
                       @selector(dataTaskWithRequest:completionHandler:), (IMP)NrcDtReqComp);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithURL:completionHandler:",
                       @selector(dataTaskWithURL:completionHandler:), (IMP)NrcDtUrlComp);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithRequest:",
                       @selector(dataTaskWithRequest:), (IMP)NrcDtReq);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithURL:",
                       @selector(dataTaskWithURL:), (IMP)NrcDtUrl);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession downloadTaskWithRequest:",
                       @selector(downloadTaskWithRequest:), (IMP)NrcDlReq);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession downloadTaskWithURL:",
                       @selector(downloadTaskWithURL:), (IMP)NrcDlUrl);

    @try {
        Class asset = NSClassFromString(@"AVURLAsset");
        if (asset != Nil) {
            NrcHookInstance(asset, NSSelectorFromString(@"initWithURL:options:"),
                            (IMP)NrcAssetInit, NULL);
        }
        Class item = NSClassFromString(@"AVPlayerItem");
        if (item != Nil) {
            NrcHookInstance(item, NSSelectorFromString(@"initWithURL:"), (IMP)NrcItemInit, NULL);
            NrcHookClass(item, NSSelectorFromString(@"playerItemWithURL:"), (IMP)NrcItemCls, NULL);
        }
        Class player = NSClassFromString(@"AVPlayer");
        if (player != Nil) {
            NrcHookInstance(player, NSSelectorFromString(@"initWithURL:"), (IMP)NrcPlayerInit, NULL);
            NrcHookClass(player, NSSelectorFromString(@"playerWithURL:"), (IMP)NrcPlayerCls, NULL);
        }
        NrcLogC("[STAGE2] AVFoundation(asset=%d item=%d player=%d)",
                asset != Nil ? 1 : 0, item != Nil ? 1 : 0, player != Nil ? 1 : 0);
    } @catch (NSException *e) {
        NrcLogC("[ERR] Stage2 AVFoundation 异常: %s",
                e.reason != nil ? e.reason.UTF8String : "?");
    }

    NrcLogC("[STAGE2] <<< 完成");
}

static void NrcStage3(void) {
    NrcLogC("[STAGE3] >>> 开始：全量捕获 API 清扫");
    @try {
        NrcSweepCapturedAPIs();
    } @catch (NSException *e) {
        NrcLogC("[ERR] Stage3 清扫异常: %s",
                e.reason != nil ? e.reason.UTF8String : "?");
    }
    NrcLogC("[STAGE3] <<< 完成");
}

/* ============================== 入口 ==============================
 * 这里是全 dylib 唯一的「加载期」代码，必须极轻。
 * ├─ NrcInitLogPath : getenv + snprintf，纯 C
 * ├─ NrcBumpCrashCount : fopen/fscanf/fprintf，纯 C
 * ├─ NrcLogC        : open/write/fsync，纯 C
 * └─ NrcScheduleAfter : dispatch_after，libdispatch 在 dyld 早期就绪
 * 除此之外一行 ObjC 消息、一次 runtime 枚举都没有 —— 不碰 runtime 就不会
 * 在 dyld 持锁期间重入 +initialize，也就不会看门狗超时。
 * ================================================================= */

__attribute__((constructor))
static void NrcEntry(void) {
    NrcInitLogPath();
    NrcBumpCrashCount();
    gMinimalMode = (gCrashCount >= NRC_CRASH_MINIMAL);

    NrcLogC("================================================================");
    NrcLogC("[BOOT] NoRecBypass %s · pid=%d · prog=%s · 崩溃计数=%d · 最小模式=%s",
            NRC_VERSION, (int)getpid(), getprogname(),
            gCrashCount, gMinimalMode ? "是" : "否");
    NrcLogC("[BOOT] 日志文件 %s", gLogPath);
    NrcLogC("[BOOT] 加载期不做任何 runtime 操作，将在 App 起来后分三级安装 hook");
    NrcLogC("================================================================");

    NrcScheduleAfter(NRC_T_STAGE1, YES, ^{
        @try {
            NrcStage1();
        } @catch (NSException *e) {
            NrcLogC("[ERR] Stage1 顶层异常: %s",
                    e.reason != nil ? e.reason.UTF8String : "?");
        }
    });

    if (!gMinimalMode) {
        NrcScheduleAfter(NRC_T_STAGE2, YES, ^{
            @try {
                NrcStage2();
            } @catch (NSException *e) {
                NrcLogC("[ERR] Stage2 顶层异常: %s",
                        e.reason != nil ? e.reason.UTF8String : "?");
            }
        });
        NrcScheduleAfter(NRC_T_STAGE3, NO, ^{
            @try {
                NrcStage3();
            } @catch (NSException *e) {
                NrcLogC("[ERR] Stage3 顶层异常: %s",
                        e.reason != nil ? e.reason.UTF8String : "?");
            }
        });
    } else {
        NrcLogC("[GUARD] 连续 %d 次启动未存活，本次只装最小集（录屏绕过），网络与清扫模块全部跳过",
                gCrashCount);
    }

    NrcClearCrashCountLater();
}
