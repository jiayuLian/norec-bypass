/* ---------------------------------------------------------------------------
 * NrcStub — 空壳诊断 dylib
 *
 * 目的非常明确：只回答一个问题 ——
 *   「抖音能不能带着一个 dylib 正常启动？」
 *
 * 所以这里刻意把内容压到物理极限：
 *   · 没有任何 Foundation / ObjC 调用（连 NSLog 都不用）
 *   · 没有任何 hook、没有 swizzle、没有 objc_getClassList
 *   · 没有任何文件 IO、socket、线程、定时器
 *   · 只有一个裸 write(2) 系统调用
 *
 * 判读方法：
 *   注入 Stub 后抖音仍然闪退  → 问题不在我们的代码，而在「注入行为本身」
 *                              （抖音反注入/完整性校验、TrollFools 重签、
 *                                或 CydiaSubstrate/ElleKit 依赖缺失）
 *   注入 Stub 后抖音正常启动  → 加载路径没问题，是我们的 hook 代码崩的，
 *                              换用 NoRecBypass 加固版
 * ------------------------------------------------------------------------- */

#include <unistd.h>

__attribute__((constructor))
static void NrcStubEntry(void) {
    /* 裸系统调用：连 stdio 缓冲区都不碰，启动期零副作用 */
    const char *msg = "[NRC-STUB] dylib loaded ok\n";
    size_t n = 0;
    while (msg[n] != '\0') {
        n++;
    }
    ssize_t ignored = write(STDERR_FILENO, msg, n);
    (void)ignored;
}
