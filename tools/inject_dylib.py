#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RNA · 纯 Python Mach-O dylib 注入器（Linux / Windows 可用，不需要 macOS）

给一个 arm64 单架构 Mach-O 可执行文件追加一条 LC_LOAD_DYLIB，
让 App 启动时自动 dlopen 我们的 dylib。

实现要点：
  * 只在头部 padding 里写新 load command —— 文件其它偏移全部不变，
    所以 __TEXT/__DATA/__LINKEDIT 的 vmaddr、offset 完全不受影响。
  * 新命令的长度按 8 字节对齐（Mach-O 要求 cmdsize 与 sizeofcmds 都 8 对齐）。
  * dylib 安装路径内联在命令里（lc_str 相对命令起始偏移），不占额外空间。

用法：
    python3 inject_dylib.py <Mach-O 可执行文件> <安装路径>
例：
    python3 inject_dylib.py Payload/ChinaUnicom4.x.app/ChinaUnicom4.x \
        @executable_path/Frameworks/RNAUnicomPay.dylib
"""

import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_CODE_SIGNATURE = 0x1D


def align8(n):
    return (n + 7) & ~7


def parse_header(data):
    if len(data) < 32:
        raise ValueError('文件太小，不是 Mach-O')
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        raise ValueError('这是 fat/通用二进制，请先用 lipo/thin 拆出 arm64 单片')
    if magic == MH_CIGAM_64:
        raise ValueError('大端 Mach-O，未支持')
    if magic != MH_MAGIC_64:
        raise ValueError('不是 64 位 Mach-O（magic=%#x）' % magic)
    cputype, cpusub, ftype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<7I', data, 4)
    if cputype != 0x0100000C:
        raise ValueError('不是 arm64（cputype=%#x）' % cputype)
    return dict(ncmds=ncmds, sizeofcmds=sizeofcmds, ftype=ftype, flags=flags)


def find_text_padding_end(data, ncmds):
    """返回 __TEXT 里偏移最小的 section 文件偏移 = load commands 区之后可用的空洞上界"""
    off = 32
    lowest = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if size < 8:
            raise ValueError('load command 长度非法')
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b'\0')
            nsects = struct.unpack_from('<I', data, off + 64)[0]
            so = off + 72
            for _s in range(nsects):
                secname = data[so:so + 16].rstrip(b'\0')
                sec_off = struct.unpack_from('<I', data, so + 48)[0]
                if segname == b'__TEXT' and sec_off:
                    name = secname.decode('latin1')
                    if name in ('__text', '__const', '__cstring', '__objc_methname',
                                '__objc_classname', '__stubs', '__ustring'):
                        lowest = sec_off if lowest is None else min(lowest, sec_off)
                so += 80
        off += size
    if lowest is None:
        raise ValueError('没找到 __TEXT 的可定位 section，无法确定 padding')
    return lowest


def build_dylib_command(install_path):
    name = install_path.encode('utf-8')
    cmdsize = align8(24 + len(name) + 1)
    cmd = bytearray(cmdsize)
    # struct dylib_command { uint32 cmd; uint32 cmdsize;
    #   struct dylib { union lc_str name; uint32 timestamp;
    #                  uint32 current_version; uint32 compatibility_version; } dylib; }
    struct.pack_into('<IIIIII', cmd, 0, LC_LOAD_DYLIB, cmdsize, 24, 0, 0x10000, 0x10000)
    cmd[24:24 + len(name)] = name
    return bytes(cmd)


def inject(path, install_path, dry_run=False):
    data = bytearray(open(path, 'rb').read())
    hdr = parse_header(data)
    ncmds, sizeofcmds = hdr['ncmds'], hdr['sizeofcmds']

    lc_end = 32 + sizeofcmds
    pad_end = find_text_padding_end(data, ncmds)
    lc = build_dylib_command(install_path)

    free = pad_end - lc_end
    if free < len(lc):
        raise ValueError('头部 padding 不够：需要 %d 字节，只剩 %d 字节' % (len(lc), free))

    # 防重复注入
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == LC_LOAD_DYLIB:
            nm_off = struct.unpack_from('<I', data, off + 8)[0]
            nm = data[off + nm_off:off + size].split(b'\0')[0].decode('utf-8', 'replace')
            if nm == install_path:
                print('[=] 已存在同名 LC_LOAD_DYLIB，跳过')
                return False
        off += size

    data[lc_end:lc_end + len(lc)] = lc
    struct.pack_into('<II', data, 16, ncmds + 1, sizeofcmds + len(lc))  # ncmds, sizeofcmds

    if not dry_run:
        open(path, 'wb').write(bytes(data))

    print('[+] 注入完成')
    print('    ncmds      : %d -> %d' % (ncmds, ncmds + 1))
    print('    sizeofcmds : %d -> %d (padding %d 字节可用)' % (sizeofcmds, sizeofcmds + len(lc), free))
    print('    load path  : %s' % install_path)
    return True


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    inject(sys.argv[1], sys.argv[2], dry_run=('--dry-run' in sys.argv))


if __name__ == '__main__':
    main()
