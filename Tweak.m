/* ---------------------------------------------------------------------------
 * NoRecBypass (NRC) — 抖音小程序「多来看点」录屏限制绕过 + 进程内流量取证
 *
 * 目标设备：iPhone · iOS 15.4.1 · TrollStore（非越狱）· 注入宿主 = 抖音
 *
 * ── 为什么不用 Logos ──────────────────────────────────────────────────────
 * Logos 的 %hook 会生成对 MSHookMessageEx / MSGetImageByName 的引用，于是 dylib
 * 多出一条加载命令 /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate。
 * TrollStore / TrollFools 只是签名劫持、不是越狱，设备上根本没有这个 framework，
 * dyld 会在加载期直接报 Library not loaded → 抖音启动即崩。
 * 所以这里全部手写 objc runtime swizzle，一个 Logos 指令都不用。
 *
 * ── 三件事 ────────────────────────────────────────────────────────────────
 * 1) 录屏检测绕过（核心）
 *    抖音小程序用 -[UIScreen isCaptured] 判断是否正在录屏；为真就把播放面涂黑
 *    并弹「付费内容仅支持在小程序内观看」。把该方法恒返回 NO，并把
 *    UIScreenCapturedDidChangeNotification 的观察者注册一并拦掉（双保险）。
 *
 * 2) 进程内流量取证
 *    小游戏/小程序的视频走抖音自研 TTNet 直连 socket，不理会系统 HTTP 代理，
 *    且做证书固定 —— 所以抓包抓不到。但业务接口是走系统网络栈的（抓包时能看到
 *    它们连到代理并握手失败，正好说明它们走的是 NSURLSession）。进程内 hook
 *    NSURLSession / AVFoundation，读到的是解密后的明文，证书固定完全不起作用。
 *    这样就能拿到播放接口响应里真正的 m3u8 / mp4 地址。
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
#import <stdio.h>
#import <stdarg.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <ctype.h>

#define NRC_VERSION  @"1.0.2"
#define NRC_PORT     8899
#define NRC_URL_MAX  5000
#define NRC_BODY_MAX 200

/* ============================== 前向声明 ==============================
 * 单文件无头文件，C99 起不支持隐式函数声明 —— 定义在后面的函数必须先声明。
 * ==================================================================== */
static void        NrcLog(NSString *fmt, ...);
static NSString   *NrcLogPath(void);
static BOOL        NrcHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOld);
static BOOL        NrcHookClass(Class cls, SEL sel, IMP newImp, IMP *outOld);
static BOOL        NrcClassDefines(Class cls, SEL sel);
static int         NrcHookCluster(NSString *needle, SEL sel, IMP newImp, IMP *outOld);
static BOOL        NrcAlreadyLoaded(void);
static NSString   *NrcWiFiAddress(void);
static void        NrcNoteRequest(NSURLRequest *req);
static void        NrcNoteResponse(NSURLRequest *req, NSURLResponse *resp, NSData *data);
static void        NrcServerLoop(void);
static void        NrcServeClient(int cfd);
static void        NrcSendAll(int cfd, const void *data, size_t len);
static void        NrcStartHttpServer(void);
static void        NrcInstallHooks(void);
static void        NrcHookClusterOnce(NSString *needle, NSString *label, SEL sel, IMP newImp, IMP *outOld);
static void        NrcSweepCapturedAPIs(void);
static void        NrcReassertCaptureHooks(void);
static void        NrcStartMaintenance(void);
static BOOL        NrcSelLooksLikeCapturedCheck(const char *selName, const char *clsName);

/* ================================ 日志 ================================ */

static NSString *gLogPath = nil;
static os_unfair_lock gLogLock = OS_UNFAIR_LOCK_INIT;
static int gCapturedCalls = 0;
static int gUrlCount = 0;
static int gBodyCount = 0;

static NSString *NrcLogPath(void) {
    if (gLogPath) {
        return gLogPath;
    }
    NSMutableArray *cands = [NSMutableArray array];
    /* 非越狱设备上 /var/mobile 多半写不了；TrollFools 注入的包带 platform-application
       时能写。逐个试，第一个能打开的就用。 */
    [cands addObject:@"/var/mobile/Documents/norec.log"];
    [cands addObject:@"/var/mobile/Media/norec.log"];
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count > 0) {
        [cands addObject:[docs[0] stringByAppendingPathComponent:@"norec.log"]];
    }
    [cands addObject:[NSTemporaryDirectory() stringByAppendingPathComponent:@"norec.log"]];
    [cands addObject:@"/tmp/norec.log"];
    for (NSString *p in cands) {
        FILE *t = fopen(p.UTF8String, "a");
        if (t) {
            fclose(t);
            gLogPath = [p copy];
            return gLogPath;
        }
    }
    gLogPath = [@"/tmp/norec.log" copy];
    return gLogPath;
}

static void NrcLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (msg.length == 0) {
        return;
    }
    NSLog(@"[NRC] %@", msg);

    NSString *path = NrcLogPath();
    os_unfair_lock_lock(&gLogLock);
    FILE *f = fopen(path.UTF8String, "a");
    if (f) {
        fprintf(f, "%s\n", msg.UTF8String);
        fclose(f);
    }
    os_unfair_lock_unlock(&gLogLock);
}

/* ============================== swizzle ============================== */

static BOOL NrcClassDefines(Class cls, SEL sel) {
    BOOL found = NO;
    unsigned int n = 0;
    Method *ms = class_copyMethodList(cls, &n);
    if (ms) {
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
   否则该类自己有实现，直接原地换 IMP。这样绝不会误改父类方法。 */
static BOOL NrcHookInstance(Class cls, SEL sel, IMP newImp, IMP *outOld) {
    if (!cls || !sel) {
        return NO;
    }
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        return NO;
    }
    IMP old = method_getImplementation(m);
    if (class_addMethod(cls, sel, newImp, method_getTypeEncoding(m))) {
        if (outOld) {
            *outOld = old;
        }
        return YES;
    }
    IMP prev = method_setImplementation(class_getInstanceMethod(cls, sel), newImp);
    if (outOld) {
        *outOld = prev;
    }
    return YES;
}

static BOOL NrcHookClass(Class cls, SEL sel, IMP newImp, IMP *outOld) {
    if (!cls || !sel) {
        return NO;
    }
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        return NO;
    }
    Class meta = object_getClass(cls);
    IMP old = method_getImplementation(m);
    if (class_addMethod(meta, sel, newImp, method_getTypeEncoding(m))) {
        if (outOld) {
            *outOld = old;
        }
        return YES;
    }
    IMP prev = method_setImplementation(class_getClassMethod(cls, sel), newImp);
    if (outOld) {
        *outOld = prev;
    }
    return YES;
}

/* NSURLSession 是 class cluster：真正实现挂在 __NSCFURLSession 这类具体类上，
   只 swizzle 抽象基类是拦不到的。所以按名字枚举，只 hook「自己直接定义了该方法」
   的类（避免重复 hook 与 IMP 串线）。一个都没命中时再退回 hook 基类。 */
static int NrcHookCluster(NSString *needle, SEL sel, IMP newImp, IMP *outOld) {
    int hooked = 0;
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return 0;
    }
    Class *list = (Class *)calloc((size_t)count, sizeof(Class));
    if (!list) {
        return 0;
    }
    objc_getClassList(list, count);
    for (int i = 0; i < count; i++) {
        Class c = list[i];
        const char *nm = class_getName(c);
        if (!nm) {
            continue;
        }
        NSString *name = [NSString stringWithUTF8String:nm];
        if (!name || ![name containsString:needle]) {
            continue;
        }
        if (!NrcClassDefines(c, sel)) {
            continue;
        }
        if (NrcHookInstance(c, sel, newImp, outOld)) {
            hooked++;
            NrcLog(@"[HOOK] -[%@ %@]", name, NSStringFromSelector(sel));
        }
    }
    free(list);
    if (hooked == 0) {
        Class base = NSClassFromString(needle);
        if (base && NrcHookInstance(base, sel, newImp, outOld)) {
            hooked++;
            NrcLog(@"[HOOK] -[%@ %@] (base fallback)", needle, NSStringFromSelector(sel));
        }
    }
    return hooked;
}

static void NrcHookClusterOnce(NSString *needle, NSString *label, SEL sel, IMP newImp, IMP *outOld) {
    int n = NrcHookCluster(needle, sel, newImp, outOld);
    NrcLog(@"[HOOK] %@ -> %d 个类", label, n);
}

/* ========================= 1. 录屏检测绕过 ========================= */

static BOOL NrcIsCapturedFalse(id self, SEL _cmd) {
    gCapturedCalls++;
    if (gCapturedCalls <= 30 || (gCapturedCalls % 50) == 0) {
        NrcLog(@"[HIT] -[%@ isCaptured] -> NO  (第 %d 次)",
               NSStringFromClass([self class]), gCapturedCalls);
    }
    return NO;
}

static BOOL NrcIsCapturedUnderscoreFalse(id self, SEL _cmd) {
    NrcLog(@"[HIT] -[%@ _isCaptured] -> NO", NSStringFromClass([self class]));
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

static IMP gOrigAddObsSel = NULL;
static void NrcAddObsSel(id self, SEL _cmd, id observer, SEL sel, NSString *name, id object) {
    if (NrcIsCaptureNotify(name)) {
        NrcLog(@"[BLOCK] addObserver:selector:name:object: for %@", name);
        return;
    }
    ((void (*)(id, SEL, id, SEL, NSString *, id))gOrigAddObsSel)(self, _cmd, observer, sel, name, object);
}

typedef void (^NrcNotifyBlock)(NSNotification *note);
static IMP gOrigAddObsBlk = NULL;
static id NrcAddObsBlk(id self, SEL _cmd, NSString *name, id object,
                       NSOperationQueue *queue, NrcNotifyBlock block) {
    if (NrcIsCaptureNotify(name)) {
        NrcLog(@"[BLOCK] addObserverForName:object:queue:usingBlock: for %@", name);
        return nil;
    }
    return ((id (*)(id, SEL, NSString *, id, NSOperationQueue *, NrcNotifyBlock))gOrigAddObsBlk)
        (self, _cmd, name, object, queue, block);
}

/* ---- 通用「捕获检测」清扫 --------------------------------------------------
 * UIScreen 是官方入口，但各家普遍会再包一层私有实现：_isCaptured、
 * isScreenCaptured、isBeingCaptured… 甚至是自己写的 wrapper 类。
 * 只 hook UIScreen 一旦漏掉那层包装，画面照样被涂黑。
 *
 * 这里对全量已加载类做清扫：凡是「返回 BOOL、无参、名字形如
 * is*captur(e|ed|ing)」的方法，一律恒返回 NO。
 * 名字过滤写得很窄（"captur" 之后只允许空 / e / ed / ing / edby），
 * 免得误伤 isCaptureSessionSupported 这类无关方法。
 * ------------------------------------------------------------------------- */

static int gSweepGens  = 0;
static int gSweepTotal = 0;

static void NrcLowerCopy(const char *src, char *dst, size_t cap) {
    if (!dst || cap == 0) {
        return;
    }
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < cap; i++) {
            char ch = src[i];
            dst[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        }
    }
    dst[i] = '\0';
}

static BOOL NrcSelLooksLikeCapturedCheck(const char *selName, const char *clsName) {
    if (!selName || !clsName) {
        return NO;
    }
    char low[192];
    NrcLowerCopy(selName, low, sizeof(low));

    const char *hit = strstr(low, "captur");
    if (hit) {
        const char *tail = hit + 6;              /* "captur" 之后的部分 */
        if (tail[0] == '\0') {
            return YES;                          /* isCapture / _isCapture */
        }
        if (tail[0] == 'e' && (tail[1] == '\0'
                               || strcmp(tail + 1, "d") == 0
                               || strcmp(tail + 1, "dby") == 0)) {
            return YES;                          /* isCaptured / isCapturedBy… */
        }
        if (tail[0] == 'i' && strcmp(tail + 1, "ng") == 0) {
            return YES;                          /* isCapturing */
        }
        return NO;
    }

    /* Screen* 类上的 is*record* 一并覆盖（私有录屏 API 常挂在这里） */
    char lcls[192];
    NrcLowerCopy(clsName, lcls, sizeof(lcls));
    if (strstr(lcls, "screen") && strstr(low, "record")) {
        return YES;
    }
    return NO;
}

static int gSweepHits = 0;
static BOOL NrcFalseSweep(id self, SEL _cmd) {
    gSweepHits++;
    if (gSweepHits <= 40 || (gSweepHits % 100) == 0) {
        NrcLog(@"[HIT] -[%@ %@] -> NO (sweep 第 %d 次)",
               NSStringFromClass([self class]), NSStringFromSelector(_cmd), gSweepHits);
    }
    return NO;
}

static void NrcSweepCapturedAPIs(void) {
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) {
        return;
    }
    Class *list = (Class *)calloc((size_t)count, sizeof(Class));
    if (!list) {
        return;
    }
    objc_getClassList(list, count);

    int hooked = 0;
    for (int i = 0; i < count; i++) {
        Class c = list[i];
        const char *cn = class_getName(c);
        if (!cn || strncmp(cn, "Nrc", 3) == 0) {
            continue;                            /* 别扫自己 */
        }
        unsigned int mn = 0;
        Method *ms = class_copyMethodList(c, &mn);
        if (!ms) {
            continue;
        }
        for (unsigned int j = 0; j < mn; j++) {
            SEL s = method_getName(ms[j]);
            const char *sn = sel_getName(s);
            if (!NrcSelLooksLikeCapturedCheck(sn, cn)) {
                continue;
            }
            /* 必须是「返回 BOOL、0 个参数」：类型编码形如 c@: / B@: / b@: */
            const char *enc = method_getTypeEncoding(ms[j]);
            if (!enc || strlen(enc) != 3 || enc[1] != '@' || enc[2] != ':') {
                continue;
            }
            if (enc[0] != 'c' && enc[0] != 'B' && enc[0] != 'b') {
                continue;
            }
            if (NrcHookInstance(c, s, (IMP)NrcFalseSweep, NULL)) {
                hooked++;
                if (hooked <= 40) {
                    NrcLog(@"[SWEEP] -[%s %s] -> NO", cn, sn);
                }
            }
        }
        free(ms);
    }
    free(list);

    gSweepGens++;
    gSweepTotal += hooked;
    NrcLog(@"[SWEEP] 第 %d 轮：本轮覆盖 %d 个方法，累计 %d", gSweepGens, hooked, gSweepTotal);
}

/* 抖音有反注入逻辑，可能把自己的实现换回去；所以定期重申一遍。 */
static void NrcReassertCaptureHooks(void) {
    Class screen = NSClassFromString(@"UIScreen");
    if (!screen) {
        return;
    }
    NrcHookInstance(screen, NSSelectorFromString(@"isCaptured"),  (IMP)NrcIsCapturedFalse, NULL);
    NrcHookInstance(screen, NSSelectorFromString(@"_isCaptured"), (IMP)NrcIsCapturedUnderscoreFalse, NULL);
}

static dispatch_source_t gMaintTimer = NULL;

static void NrcStartMaintenance(void) {
    if (gMaintTimer) {
        return;
    }
    dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                 dispatch_get_main_queue());
    if (!t) {
        NrcLog(@"[HOOK] 维护定时器创建失败（不影响其他功能）");
        return;
    }
    dispatch_source_set_timer(t,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8ull * NSEC_PER_SEC)),
                              (uint64_t)(5ull * NSEC_PER_SEC),
                              (uint64_t)(500ull * NSEC_PER_MSEC));
    __block int tick = 0;
    dispatch_source_set_event_handler(t, ^{
        tick++;
        NrcReassertCaptureHooks();
        if (tick == 2 || tick == 6 || tick == 18 || tick == 60) {
            NrcSweepCapturedAPIs();
        }
    });
    gMaintTimer = t;
    dispatch_resume(t);
    NrcLog(@"[HOOK] 维护定时器已启动：每 5s 重申 isCaptured=NO，并在第 10/30/90/300s 重扫");
}

/* ========================= 2. 进程内流量取证 ========================= */

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
    NSString *method = req.HTTPMethod.length ? req.HTTPMethod : @"GET";
    NrcLog(@"[REQ] %@ %@", method, shown);
}

static void NrcNoteResponse(NSURLRequest *req, NSURLResponse *resp, NSData *data) {
    NSString *u = req.URL.absoluteString;
    NSInteger code = 0;
    if ([resp respondsToSelector:@selector(statusCode)]) {
        code = (NSInteger)[(NSHTTPURLResponse *)resp statusCode];
    }
    NSString *mime = resp.MIMEType ? resp.MIMEType : @"?";
    NrcLog(@"[RESP] %ld %luB %@ %@", (long)code, (unsigned long)data.length, mime, u);

    /* 最终落地 URL 与原始 URL 不同 = 发生过重定向。m3u8/mp4 常常被 302 到带签名的
       CDN 地址，这条日志往往就是我们要的「真播放地址」。 */
    NSString *finalUrl = resp.URL.absoluteString;
    if (finalUrl.length && ![finalUrl isEqualToString:u]) {
        NrcLog(@"[REDIR] %@", finalUrl.length > 900 ? [finalUrl substringToIndex:900] : finalUrl);
    }

    if (!data || data.length == 0 || data.length > 524288 || gBodyCount >= NRC_BODY_MAX) {
        return;
    }
    NSString *lm = mime.lowercaseString;
    BOOL textual = ([lm containsString:@"json"] || [lm containsString:@"text"]
                    || [lm containsString:@"javascript"] || [lm containsString:@"xml"]);
    if (!textual) {
        return;
    }
    NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!body) {
        body = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    }
    if (body.length == 0) {
        return;
    }
    gBodyCount++;
    if (body.length > 4000) {
        body = [body substringToIndex:4000];
    }
    NrcLog(@"[BODY #%d] %@\n%@", gBodyCount, u, body);
}

typedef void (^NrcDataBlock)(NSData *data, NSURLResponse *response, NSError *error);

static IMP gOrigDtReqComp = NULL;
static id NrcDtReqComp(id self, SEL _cmd, NSURLRequest *req, NrcDataBlock cb) {
    NrcNoteRequest(req);
    NrcDataBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        NrcNoteResponse(req, resp, data);
        if (cb) {
            cb(data, resp, err);
        }
    };
    return ((id (*)(id, SEL, NSURLRequest *, NrcDataBlock))gOrigDtReqComp)(self, _cmd, req, wrapped);
}

static IMP gOrigDtUrlComp = NULL;
static id NrcDtUrlComp(id self, SEL _cmd, NSURL *url, NrcDataBlock cb) {
    NSURLRequest *req = url ? [NSURLRequest requestWithURL:url] : nil;
    if (req) {
        NrcNoteRequest(req);
    }
    NrcDataBlock wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (req) {
            NrcNoteResponse(req, resp, data);
        }
        if (cb) {
            cb(data, resp, err);
        }
    };
    return ((id (*)(id, SEL, NSURL *, NrcDataBlock))gOrigDtUrlComp)(self, _cmd, url, wrapped);
}

static IMP gOrigDtReq = NULL;
static id NrcDtReq(id self, SEL _cmd, NSURLRequest *req) {
    NrcNoteRequest(req);
    return ((id (*)(id, SEL, NSURLRequest *))gOrigDtReq)(self, _cmd, req);
}

static IMP gOrigDtUrl = NULL;
static id NrcDtUrl(id self, SEL _cmd, NSURL *url) {
    NSURLRequest *req = url ? [NSURLRequest requestWithURL:url] : nil;
    if (req) {
        NrcNoteRequest(req);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigDtUrl)(self, _cmd, url);
}

/* downloadTask 也要记：有些播放器先把 m3u8 落到沙盒再喂给 AVPlayer。 */
static IMP gOrigDlReq = NULL;
static id NrcDlReq(id self, SEL _cmd, NSURLRequest *req) {
    NrcNoteRequest(req);
    return ((id (*)(id, SEL, NSURLRequest *))gOrigDlReq)(self, _cmd, req);
}

static IMP gOrigDlUrl = NULL;
static id NrcDlUrl(id self, SEL _cmd, NSURL *url) {
    NSURLRequest *req = url ? [NSURLRequest requestWithURL:url] : nil;
    if (req) {
        NrcNoteRequest(req);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigDlUrl)(self, _cmd, url);
}

/* AVFoundation：抖音小程序播放器若走 AVPlayer，这里能直接拿到媒体地址。
   用 NSClassFromString 而不是 import，避免多链一个 framework。 */
static IMP gOrigAssetInit = NULL;
static id NrcAssetInit(id self, SEL _cmd, NSURL *url, NSDictionary *opts) {
    if (url.absoluteString.length) {
        NrcLog(@"[AV] AVURLAsset initWithURL: %@", url.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *, NSDictionary *))gOrigAssetInit)(self, _cmd, url, opts);
}

static IMP gOrigItemInit = NULL;
static id NrcItemInit(id self, SEL _cmd, NSURL *url) {
    if (url.absoluteString.length) {
        NrcLog(@"[AV] AVPlayerItem initWithURL: %@", url.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigItemInit)(self, _cmd, url);
}

static IMP gOrigItemCls = NULL;
static id NrcItemCls(id self, SEL _cmd, NSURL *url) {
    if (url.absoluteString.length) {
        NrcLog(@"[AV] AVPlayerItem playerItemWithURL: %@", url.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigItemCls)(self, _cmd, url);
}

static IMP gOrigPlayerInit = NULL;
static id NrcPlayerInit(id self, SEL _cmd, NSURL *url) {
    if (url.absoluteString.length) {
        NrcLog(@"[AV] AVPlayer initWithURL: %@", url.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigPlayerInit)(self, _cmd, url);
}

static IMP gOrigPlayerCls = NULL;
static id NrcPlayerCls(id self, SEL _cmd, NSURL *url) {
    if (url.absoluteString.length) {
        NrcLog(@"[AV] AVPlayer playerWithURL: %@", url.absoluteString);
    }
    return ((id (*)(id, SEL, NSURL *))gOrigPlayerCls)(self, _cmd, url);
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
        if (inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host))) {
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
    NrcLog(@"[HTTP] %s", path);

    NSData *body = nil;
    NSString *ctype = @"text/plain; charset=utf-8";
    if (strcmp(path, "/") == 0 || strncmp(path, "/norec.log", 10) == 0) {
        NSString *logPath = NrcLogPath();
        body = [NSData dataWithContentsOfFile:logPath];
        if (!body) {
            body = [@"(日志还没生成或读不到)" dataUsingEncoding:NSUTF8StringEncoding];
        }
        if (body.length > 2097152) {
            body = [body subdataWithRange:NSMakeRange(body.length - 2097152, 2097152)];
        }
    } else {
        NSString *page = [NSString stringWithFormat:
            @"<!doctype html><meta charset=utf-8><title>NRC</title>"
            @"<style>body{font:16px -apple-system;margin:24px;line-height:1.7}</style>"
            @"<h2>NoRecBypass %@</h2>"
            @"<p>日志文件：<code>%@</code>（%lu 字节）</p>"
            @"<p><a href=\"/norec.log\">查看日志</a></p>"
            @"<p>先在抖音里播一集，再回来看这里。</p>",
            NRC_VERSION, NrcLogPath(),
            (unsigned long)[[NSData dataWithContentsOfFile:NrcLogPath()] length]];
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
        NrcLog(@"[HTTP] socket 创建失败");
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
        NrcLog(@"[HTTP] bind %d 失败（errno %d）", NRC_PORT, errno);
        close(sfd);
        return;
    }
    if (listen(sfd, 16) != 0) {
        NrcLog(@"[HTTP] listen 失败");
        close(sfd);
        return;
    }
    NSString *ip = NrcWiFiAddress();
    NrcLog(@"[HTTP] 已监听 0.0.0.0:%d —— 电脑浏览器打开 http://%@:%d/ 读日志",
           NRC_PORT, ip.length ? ip : @"<手机IP>", NRC_PORT);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            continue;
        }
        NrcServeClient(cfd);
        close(cfd);
    }
}

static void NrcStartHttpServer(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        [NSThread sleepForTimeInterval:3.0];
        NrcServerLoop();
    });
}

/* ============================== 入口 ============================== */

static BOOL NrcAlreadyLoaded(void) {
    /* 运行时注册一个哨兵类：不能用 @implementation 定义，否则 dylib 自己第一次
       加载时 NSClassFromString 立刻就能查到，会把自己挡在门外，整个 dylib 变哑巴。 */
    if (NSClassFromString(@"NrcLoadGate")) {
        return YES;
    }
    Class c = objc_allocateClassPair([NSObject class], "NrcLoadGate", 0);
    if (!c) {
        return NO;
    }
    objc_registerClassPair(c);
    return NO;
}

static void NrcInstallHooks(void) {
    Class screen = NSClassFromString(@"UIScreen");
    if (screen) {
        SEL selCaptured = NSSelectorFromString(@"isCaptured");
        SEL selCapturedU = NSSelectorFromString(@"_isCaptured");
        BOOL ok = NrcHookInstance(screen, selCaptured, (IMP)NrcIsCapturedFalse, NULL);
        NrcLog(@"[HOOK] -[UIScreen isCaptured] -> %@", ok ? @"OK" : @"未找到");
        BOOL okU = NrcHookInstance(screen, selCapturedU, (IMP)NrcIsCapturedUnderscoreFalse, NULL);
        NrcLog(@"[HOOK] -[UIScreen _isCaptured] -> %@", okU ? @"OK" : @"不存在(跳过)");
    } else {
        NrcLog(@"[HOOK] 找不到 UIScreen");
    }

    /* NSNotificationCenter 万一也是 cluster，只 hook 基类会漏；按名字枚举最稳。 */
    NrcHookClusterOnce(@"NSNotificationCenter", @"NSNotificationCenter addObserver:selector:name:object:",
                       @selector(addObserver:selector:name:object:), (IMP)NrcAddObsSel, &gOrigAddObsSel);
    NrcHookClusterOnce(@"NSNotificationCenter", @"NSNotificationCenter addObserverForName:object:queue:usingBlock:",
                       @selector(addObserverForName:object:queue:usingBlock:), (IMP)NrcAddObsBlk, &gOrigAddObsBlk);

    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithRequest:completionHandler:",
                       @selector(dataTaskWithRequest:completionHandler:), (IMP)NrcDtReqComp, &gOrigDtReqComp);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithURL:completionHandler:",
                       @selector(dataTaskWithURL:completionHandler:), (IMP)NrcDtUrlComp, &gOrigDtUrlComp);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithRequest:",
                       @selector(dataTaskWithRequest:), (IMP)NrcDtReq, &gOrigDtReq);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession dataTaskWithURL:",
                       @selector(dataTaskWithURL:), (IMP)NrcDtUrl, &gOrigDtUrl);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession downloadTaskWithRequest:",
                       @selector(downloadTaskWithRequest:), (IMP)NrcDlReq, &gOrigDlReq);
    NrcHookClusterOnce(@"URLSession", @"NSURLSession downloadTaskWithURL:",
                       @selector(downloadTaskWithURL:), (IMP)NrcDlUrl, &gOrigDlUrl);

    Class asset = NSClassFromString(@"AVURLAsset");
    if (asset) {
        NrcHookInstance(asset, NSSelectorFromString(@"initWithURL:options:"),
                        (IMP)NrcAssetInit, &gOrigAssetInit);
    }
    Class item = NSClassFromString(@"AVPlayerItem");
    if (item) {
        NrcHookInstance(item, NSSelectorFromString(@"initWithURL:"), (IMP)NrcItemInit, &gOrigItemInit);
        NrcHookClass(item, NSSelectorFromString(@"playerItemWithURL:"), (IMP)NrcItemCls, &gOrigItemCls);
    }
    Class player = NSClassFromString(@"AVPlayer");
    if (player) {
        NrcHookInstance(player, NSSelectorFromString(@"initWithURL:"), (IMP)NrcPlayerInit, &gOrigPlayerInit);
        NrcHookClass(player, NSSelectorFromString(@"playerWithURL:"), (IMP)NrcPlayerCls, &gOrigPlayerCls);
    }
    NrcLog(@"[HOOK] AVFoundation(asset=%d item=%d player=%d)",
           asset ? 1 : 0, item ? 1 : 0, player ? 1 : 0);
}

__attribute__((constructor))
static void NrcEntry(void) {
    @autoreleasepool {
        if (NrcAlreadyLoaded()) {
            return;
        }
        NrcLog(@"==================================================");
        NrcLog(@"[BOOT] NoRecBypass %@ · pid %d · 宿主 %@",
               NRC_VERSION, (int)getpid(), NSProcessInfo.processInfo.processName);
        NrcLog(@"[BOOT] 日志文件 %@", NrcLogPath());
        NrcInstallHooks();
        NrcSweepCapturedAPIs();
        NrcStartHttpServer();
        NrcStartMaintenance();
        NrcLog(@"[BOOT] 初始化完成");
        NrcLog(@"==================================================");
    }
}
