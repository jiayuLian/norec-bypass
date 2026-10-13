/* ---------------------------------------------------------------------------
 * NrcLite — 极端最小化的录屏绕过（只做一件事）
 *
 * 【本文件存在的唯一理由：分离变量】
 *
 * 已知事实：
 *   NrcStub.dylib   （裸 write(2)，clang 编，ldid 签名）→ 注入抖音【正常】
 *   NoRecBypass ≤1.0.4（Theos 编，几百行 hook）        → 注入抖音【闪退】
 *
 * 这两者之间差的不是一样东西，而是一整堆：Theos 工具链、UIKit/AVFoundation 链接、
 * 全量类清扫、NSURLSession hook、socket 服务、分级安装…一次改一堆，永远定位不到。
 *
 * 所以这个文件把差异压到极限：
 *   * 用 clang 直接编，完全不经过 Theos —— 和 Stub 完全同一条工具链
 *   * 只链 Foundation，不链 UIKit / AVFoundation
 *   * 只 hook 一个类的一个方法：-[UIScreen isCaptured] → NO
 *   * 不扫类列表、不开线程、不开 socket、不碰 NSURLSession
 *   * 构造期只用纯 C 写日志，一个 ObjC 消息都不发
 *
 * 编出三个梯度包，一次注入就能确定边界：
 *
 *   NrcLite0.dylib     NRC_MODE=0   完全不装 hook（等价 Stub + ObjC/Foundation 链接）
 *                                   → 崩 ⇒ 问题在「链接了 Foundation/ObjC」
 *   NrcLite.dylib      NRC_MODE=1   在 constructor 里装 hook（最早时机）
 *                                   → 崩 ⇒ 抖音在启动早期就会因「系统类被改」而死
 *   NrcLiteLate.dylib  NRC_MODE=2   在 App 起来 +3s 后装 hook
 *                                   → 崩 ⇒ 抖音的完整性校验发生在启动之后
 *
 * 三个包里谁活着，就说明「抖音能容忍到什么程度」，后面的主程序就照着那个边界写。
 *
 * 日志两路输出：
 *   1) $HOME/Documents/nrc_lite.log   （抖音容器内；TrollStore 版 Filza 可看）
 *   2) NSLog                          （+3s 后开启；电脑 idevicesyslog 实时看）
 *
 * ── 版本锚点 ───────────────────────────────────────────────────────────── */
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

#ifndef NRC_MODE
#define NRC_MODE 1              /* 0=不装  1=构造期装  2=+3s 装 */
#endif

#define NRC_VER   "1.0.5"
#define NRC_TAG   "NrcLite"

#define NRC_STRX(x) #x
#define NRC_STR(x)  NRC_STRX(x)

/* 打进二进制里，用于校验「下载到的确实是这个模式」 */
__attribute__((used))
static const char gNrcBuildTag[] = NRC_TAG "/" NRC_VER "/mode=" NRC_STR(NRC_MODE);

static char gPath[1024] = {0};
static int  gEcho = 0;          /* 置 1 之后才敢用 NSLog（构造期绝不调用） */

/* ------------------------------- 纯 C 日志 ------------------------------- */
static void nrc_raw(const char *fmt, ...) {
    char body[1400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char line[1600];
    int n = snprintf(line, sizeof(line), "[" NRC_TAG "] %s\n", body);
    if (n <= 0) return;
    if (n > (int)sizeof(line) - 1) n = (int)sizeof(line) - 1;

    if (gPath[0]) {
        int fd = open(gPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            ssize_t w = write(fd, line, (size_t)n);
            (void)w;
            fsync(fd);          /* 崩之前最后一行必须在磁盘上 */
            close(fd);
        }
    }
    if (gEcho) {
        NSLog(@"%s", line);
    }
}

static void nrc_open_log(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    static const char *suffix[] = {
        "/Documents/nrc_lite.log",
        "/Library/nrc_lite.log",
        "/tmp/nrc_lite.log",
        "/nrc_lite.log"
    };
    for (int i = 0; i < 4; i++) {
        snprintf(gPath, sizeof(gPath), "%s%s", home, suffix[i]);
        int fd = open(gPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { close(fd); return; }
        gPath[0] = 0;
    }
}

/* ---------------------------- 唯一的那个 hook ---------------------------- */
#if NRC_MODE != 0

static BOOL nrc_isCaptured(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return NO;                  /* 永远「没在录屏」 */
}

static void nrc_install(void) {
    Class cls = objc_getClass("UIScreen");
    if (!cls) {
        nrc_raw("!! objc_getClass(\"UIScreen\") 返回 NULL");
        return;
    }
    nrc_raw("UIScreen = %p", (void *)cls);

    static const char *names[] = { "isCaptured", "_isCaptured" };
    for (int i = 0; i < 2; i++) {
        SEL sel = sel_registerName(names[i]);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) {
            nrc_raw("   -[UIScreen %s] 不存在（正常，跳过）", names[i]);
            continue;
        }
        IMP prev = method_setImplementation(m, (IMP)nrc_isCaptured);
        nrc_raw("   hook OK: -[UIScreen %s]  原 IMP = %p", names[i], (void *)prev);
    }
}

#endif /* NRC_MODE != 0 */

/* ------------------------------ 入口 ------------------------------ */
__attribute__((constructor))
static void nrc_init(void) {
    nrc_open_log();
    nrc_raw("=== loaded  build=%s  pid=%d  HOME=%s ===",
            gNrcBuildTag, (int)getpid(),
            getenv("HOME") ? getenv("HOME") : "?");

#if NRC_MODE == 1
    nrc_raw("[A1] 构造期安装 hook（最早时机）");
    nrc_install();
    nrc_raw("[A2] 构造期 hook 已装完 —— 若日志停在此行且抖音闪退，说明崩在 hook 之后");
#elif NRC_MODE == 0
    nrc_raw("[A0] NrcLite0：不装任何 hook，仅验证 Foundation/ObjC 链接");
#else
    nrc_raw("[A0] NrcLiteLate：hook 推迟到 +3s 安装");
#endif

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gEcho = 1;
        nrc_raw("--- +3s App 存活，日志开始双写 NSLog ---");

#if NRC_MODE == 2
        nrc_raw("[B1] 现在安装 hook");
        nrc_install();
        nrc_raw("[B2] hook 安装完成");
#elif NRC_MODE == 1
        nrc_raw("[B1] 构造期已装好，无额外动作");
#else
        nrc_raw("[B1] 无额外动作（本包不装 hook）");
#endif

        nrc_raw("[B3] 现在开录屏、进多来看点播一集，看画面是否还变黑");
    });
}
