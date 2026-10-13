/* ---------------------------------------------------------------------------
 * NrcTrace — 取证版：把「谁在判断录屏」和「视频地址是什么」都挖出来
 *
 * 前提：NrcLiteLate.dylib 已实测可用 —— 说明「+3s 之后再动手」是抖音能容忍的边界。
 * 本文件沿用这个边界，只加取证，不改行为。
 *
 * 四个模块（都装在 +3s 之后）：
 *
 *   A. isCaptured 现场取证（回答「谁在判断录屏」）
 *      仍然返回 NO（保持绕过），但每次被调用时打印调用栈：
 *        #1 <哪个二进制> + <符号名>
 *      前 30 次打完整栈，之后只记次数 —— 因为小程序可能每帧都在问。
 *
 *   B. NSURLProtocol 明文取证（零 swizzle）
 *      +[NSURLProtocol registerClass:] 是 iOS 官方扩展点，不修改任何类的方法表，
 *      因此不会被反篡改盯上。它能拿到所有走系统网络栈（NSURLSession）的
 *      请求 URL、请求头、响应状态、响应体（json/text 截断打印）。
 *
 *   C. AVFoundation 入口取证（-DNRC_AV=1 才编进去）
 *      +[AVURLAsset URLAssetWithURL:options:] 和 -[AVPlayerItem initWithURL:]
 *      这两个入口拿到的就是**播放器最终要放的那个 URL**。无论底层是 TTNet 裸
 *      socket 还是系统栈，URL 字符串一定得从这两个口子进来。
 *      只改 2 个方法，不扫类列表。
 *
 *   D. HTTP 日志服务（0.0.0.0:8899）
 *      电脑浏览器打开 http://<手机IP>:8899/ 直接看实时日志，不用找文件。
 *
 * 编两份：
 *   -DNRC_AV=0  ->  NrcTrace.dylib     A + B + D（最保守，先试这个）
 *   -DNRC_AV=1  ->  NrcTraceAV.dylib   A + B + C + D（加上播放器 URL 抓取）
 *
 * 日志三路：容器文件 $HOME/Documents/nrc_trace.log + NSLog + HTTP 8899
 * ------------------------------------------------------------------------- */
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>
#import <objc/message.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef NRC_AV
#define NRC_AV 0
#endif

#define NRC_VER "1.0.6"
#define NRC_TAG "NrcTrace"

#define NRC_STRX(x) #x
#define NRC_STR(x)  NRC_STRX(x)

__attribute__((used))
static const char gNrcBuildTag[] = NRC_TAG "/" NRC_VER "/av=" NRC_STR(NRC_AV);

#define NRC_RING 4000
#define NRC_LINE 512
#define NRC_PORT 8899

static char          gRing[NRC_RING][NRC_LINE];
static int           gRingN = 0;
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static char gPath[1024] = {0};
static int  gEcho = 0;
static int  gStackQuota = 30;      /* 前 30 次 isCaptured 调用打完整调用栈 */
static int  gCapCount = 0;

/* ------------------------------- 日志 ------------------------------- */
static void nrc_log(const char *fmt, ...) {
    char body[460];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char line[NRC_LINE];
    int n = snprintf(line, sizeof(line), "[" NRC_TAG "] %s\n", body);
    if (n <= 0) return;
    if (n > NRC_LINE - 1) n = NRC_LINE - 1;

    if (gPath[0]) {
        int fd = open(gPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            ssize_t w = write(fd, line, (size_t)n);
            (void)w;
            fsync(fd);
            close(fd);
        }
    }

    pthread_mutex_lock(&gLock);
    char *slot = gRing[gRingN % NRC_RING];
    memset(slot, 0, NRC_LINE);
    memcpy(slot, line, (size_t)n);
    gRingN++;
    pthread_mutex_unlock(&gLock);

    if (gEcho) NSLog(@"%s", line);
}

static void nrc_open_log(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    static const char *suffix[] = {
        "/Documents/nrc_trace.log", "/Library/nrc_trace.log",
        "/tmp/nrc_trace.log", "/nrc_trace.log"
    };
    for (int i = 0; i < 4; i++) {
        snprintf(gPath, sizeof(gPath), "%s%s", home, suffix[i]);
        int fd = open(gPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { close(fd); return; }
        gPath[0] = 0;
    }
}

/* --------------------------- A. isCaptured 取证 --------------------------- */
static void nrc_dump_stack(void) {
    void *bt[24];
    int n = backtrace(bt, 24);
    for (int i = 1; i < n && i <= 6; i++) {
        Dl_info info;
        if (dladdr(bt[i], &info) && info.dli_fname) {
            const char *img = strrchr(info.dli_fname, '/');
            img = img ? img + 1 : info.dli_fname;
            nrc_log("        #%d  %s  %s", i, img,
                    info.dli_sname ? info.dli_sname : "(无符号)");
        } else {
            nrc_log("        #%d  ?  %p", i, bt[i]);
        }
    }
}

static BOOL nrc_isCaptured(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    gCapCount++;
    if (gStackQuota > 0) {
        gStackQuota--;
        nrc_log("isCaptured 被调用（第 %d 次）—— 调用现场：", gCapCount);
        nrc_dump_stack();
    } else if (gCapCount % 120 == 0) {
        nrc_log("isCaptured 累计调用 %d 次（仍在恒返回 NO）", gCapCount);
    }
    return NO;
}

static void nrc_install_capture_hook(void) {
    Class cls = objc_getClass("UIScreen");
    if (!cls) { nrc_log("!! 找不到 UIScreen"); return; }
    static const char *names[] = { "isCaptured", "_isCaptured" };
    for (int i = 0; i < 2; i++) {
        SEL sel = sel_registerName(names[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        IMP prev = method_setImplementation(m, (IMP)nrc_isCaptured);
        nrc_log("[A] hook -[UIScreen %s]  原 IMP=%p", names[i], (void *)prev);
    }
}

/* --------------------------- B. NSURLProtocol --------------------------- */
static NSString *nrc_snip(NSData *d, NSUInteger max) {
    if (!d) return @"(无体)";
    NSUInteger n = MIN(d.length, max);
    NSString *s = [[NSString alloc] initWithData:[d subdataWithRange:NSMakeRange(0, n)]
                                        encoding:NSUTF8StringEncoding];
    if (!s) return [NSString stringWithFormat:@"(非文本 %lu 字节)", (unsigned long)d.length];
    if (d.length > max) s = [s stringByAppendingFormat:@" …(共 %lu 字节)", (unsigned long)d.length];
    return s;
}

@interface NrcURLProtocol : NSURLProtocol
@property (nonatomic, strong) NSURLSessionDataTask *nrcTask;
@end

@implementation NrcURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"NrcSeen" inRequest:request]) return NO;
    NSString *scheme = request.URL.scheme.lowercaseString;
    return [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSURLRequest *req = self.request;
    NSMutableURLRequest *fwd = [req mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"NrcSeen" inRequest:fwd];

    nrc_log("[B] → %@ %@", req.HTTPMethod ?: @"GET", req.URL.absoluteString);
    if (req.allHTTPHeaderFields.count) {
        nrc_log("[B]   请求头: %@", [req.allHTTPHeaderFields description]);
    }
    if (req.HTTPBody.length) {
        nrc_log("[B]   请求体: %@", nrc_snip(req.HTTPBody, 300));
    }

    __weak NrcURLProtocol *weakSelf = self;
    self.nrcTask = [[NSURLSession sharedSession]
        dataTaskWithRequest:fwd
          completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        NrcURLProtocol *me = weakSelf;
        if (!me) return;
        if (err) {
            nrc_log("[B] ✗ %@  → %@", req.URL.absoluteString, err.localizedDescription);
            [me.client URLProtocol:me didFailWithError:err];
            return;
        }
        NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
        nrc_log("[B] ← %ld  %@  (%lu 字节)  %@",
                (long)hr.statusCode, req.URL.absoluteString,
                (unsigned long)data.length,
                hr.allHeaderFields[@"Content-Type"] ?: @"");
        NSString *ct = [hr.allHeaderFields[@"Content-Type"] description];
        if ([ct containsString:@"json"] || [ct containsString:@"text"] ||
            [ct containsString:@"javascript"]) {
            nrc_log("[B]   响应体: %@", nrc_snip(data, 600));
        }
        [me.client URLProtocol:me didReceiveResponse:resp
             cacheStoragePolicy:NSURLCacheStorageAllowed];
        [me.client URLProtocol:me didLoadData:data];
        [me.client URLProtocolDidFinishLoading:me];
    }];
    [self.nrcTask resume];
}

- (void)stopLoading {
    [self.nrcTask cancel];
    self.nrcTask = nil;
}

@end

/* --------------------------- C. AVFoundation 入口 --------------------------- */
#if NRC_AV
typedef id (*NrcImp2)(id, SEL, id, id);
typedef id (*NrcImp1)(id, SEL, id);

static NrcImp2 gOrigAssetUrl = NULL;
static NrcImp1 gOrigPlayerItemUrl = NULL;

static id nrc_assetWithURL(id self, SEL _cmd, id url, id opts) {
    nrc_log("[C] AVURLAsset  URL = %@", [url isKindOfClass:[NSURL class]]
            ? [(NSURL *)url absoluteString] : [url description]);
    return gOrigAssetUrl ? gOrigAssetUrl(self, _cmd, url, opts) : nil;
}

static id nrc_playerItemInitWithURL(id self, SEL _cmd, id url) {
    nrc_log("[C] AVPlayerItem  URL = %@", [url isKindOfClass:[NSURL class]]
            ? [(NSURL *)url absoluteString] : [url description]);
    return gOrigPlayerItemUrl ? gOrigPlayerItemUrl(self, _cmd, url) : nil;
}

static void nrc_hook_class_method(const char *clsName, const char *selName,
                                  IMP newImp, NrcImp2 *out) {
    Class cls = objc_getClass(clsName);
    if (!cls) { nrc_log("[C] 找不到类 %s", clsName); return; }
    Method m = class_getClassMethod(cls, sel_registerName(selName));
    if (!m) { nrc_log("[C] 找不到 +[%s %s]", clsName, selName); return; }
    *out = (NrcImp2)method_setImplementation(m, newImp);
    nrc_log("[C] hook +[%s %s]", clsName, selName);
}

static void nrc_hook_inst_method(const char *clsName, const char *selName,
                                 IMP newImp, NrcImp1 *out) {
    Class cls = objc_getClass(clsName);
    if (!cls) { nrc_log("[C] 找不到类 %s", clsName); return; }
    Method m = class_getInstanceMethod(cls, sel_registerName(selName));
    if (!m) { nrc_log("[C] 找不到 -[%s %s]", clsName, selName); return; }
    *out = (NrcImp1)method_setImplementation(m, newImp);
    nrc_log("[C] hook -[%s %s]", clsName, selName);
}

static void nrc_install_av_hooks(void) {
    nrc_hook_class_method("AVURLAsset", "URLAssetWithURL:options:",
                          (IMP)nrc_assetWithURL, &gOrigAssetUrl);
    nrc_hook_inst_method("AVPlayerItem", "initWithURL:",
                         (IMP)nrc_playerItemInitWithURL, &gOrigPlayerItemUrl);
    nrc_log("[C] 注意：若抖音用自己的 TTVideoEngine，这两个口可能抓不到，"
            "那就看 [B] 的接口响应里有没有视频地址");
}
#endif

/* --------------------------- D. HTTP 日志服务 --------------------------- */
static const char *kHtmlHead =
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
    "Cache-Control: no-store\r\nConnection: close\r\n\r\n"
    "<!DOCTYPE html><html><head><meta charset=utf-8>"
    "<meta http-equiv=refresh content=3><title>NrcTrace 实时日志</title>"
    "<style>body{background:#12161c;color:#dfe4ea;font:13px/1.6 ui-monospace,Consolas,monospace;"
    "padding:14px;margin:0}h2{font:500 15px system-ui;color:#8ab4f8;margin:0 0 10px}"
    ".l{white-space:pre-wrap;word-break:break-all;border-bottom:1px solid #232a33;padding:3px 0}"
    ".hit{color:#7ee2a8}</style></head><body><h2>NrcTrace 实时日志（3 秒自动刷新）</h2>\n";

static const char *kTextHead =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
    "Cache-Control: no-store\r\nConnection: close\r\n\r\n";

static void nrc_send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, buf + off, len - off, 0);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void nrc_dump_ring(int fd, int asHtml) {
    pthread_mutex_lock(&gLock);
    int start = gRingN > NRC_RING ? gRingN - NRC_RING : 0;
    int from = gRingN - start > 800 ? gRingN - 800 : start;   /* 只发最后 800 行 */
    for (int i = from; i < gRingN; i++) {
        const char *s = gRing[i % NRC_RING];
        if (!s[0]) continue;
        if (asHtml) {
            int hot = strstr(s, "m3u8") || strstr(s, ".mp4") || strstr(s, ".ts") ||
                      strstr(s, "video") || strstr(s, "play");
            nrc_send_all(fd, hot ? "<div class=\"l hit\">" : "<div class=\"l\">",
                         hot ? 22 : 15);
            nrc_send_all(fd, s, strlen(s));
            nrc_send_all(fd, "</div>\n", 7);
        } else {
            nrc_send_all(fd, s, strlen(s));
        }
    }
    pthread_mutex_unlock(&gLock);
}

static void *nrc_server(void *arg) {
    (void)arg;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { nrc_log("[D] socket 失败"); return NULL; }
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(NRC_PORT);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        nrc_log("[D] bind %d 失败: %s", NRC_PORT, strerror(errno));
        close(s);
        return NULL;
    }
    listen(s, 8);
    nrc_log("[D] HTTP 日志服务已启动 → 电脑浏览器打开 http://<手机IP>:%d/", NRC_PORT);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { usleep(100000); continue; }
        char req[1024];
        ssize_t r = recv(c, req, sizeof(req) - 1, 0);
        if (r <= 0) { close(c); continue; }
        req[r] = 0;
        int raw = strstr(req, "/raw") != NULL;
        nrc_send_all(c, raw ? kTextHead : kHtmlHead, strlen(raw ? kTextHead : kHtmlHead));
        nrc_dump_ring(c, raw ? 0 : 1);
        if (!raw) nrc_send_all(c, "</body></html>\n", 15);
        close(c);
    }
    return NULL;
}

/* ------------------------------- 入口 ------------------------------- */
__attribute__((constructor))
static void nrc_init(void) {
    nrc_open_log();
    nrc_log("=== loaded  build=%s  pid=%d ===", gNrcBuildTag, (int)getpid());
    nrc_log("    本包带取证模块；构造期只写日志，所有安装推迟到 +3s");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gEcho = 1;
        nrc_log("--- +3s App 存活，开始安装（沿用 NrcLiteLate 验证过的时机）---");

        nrc_install_capture_hook();

        [NSURLProtocol registerClass:[NrcURLProtocol class]];
        nrc_log("[B] NSURLProtocol 已注册（官方扩展点，未 swizzle 任何类）");

#if NRC_AV
        nrc_install_av_hooks();
#else
        nrc_log("[C] 本包 NRC_AV=0，未装 AVFoundation hook");
#endif

        pthread_t th;
        if (pthread_create(&th, NULL, nrc_server, NULL) == 0) {
            pthread_detach(th);
        } else {
            nrc_log("[D] 启动日志服务线程失败");
        }

        nrc_log("--- 装完了。现在去多来看点播一集（付费集也播一下），"
                "然后看 http://<手机IP>:8899/ ---");
    });
}
