# NoRecBypass

抖音小程序（「多来看点」这类第三方短剧小程序）**录屏限制绕过** + **进程内流量取证**。

目标环境：iPhone · iOS 15.4.1 · TrollStore（非越狱）· 注入宿主 = **抖音**
注入方式：**TrollFools**（在已装 App 上原位注入 dylib 并自动重签）

---

## 它做三件事

### 1. 录屏检测绕过（核心）
抖音小程序用 `-[UIScreen isCaptured]` 判断是否正在录屏；为真就把播放面涂黑并弹
「付费内容仅支持在小程序内观看」。dylib 把该方法恒返回 `NO`，并把
`UIScreenCapturedDidChangeNotification` 的观察者注册一并拦掉（防止对方
「收到通知就无脑涂黑、不回头查 isCaptured」的写法）。

### 2. 进程内流量取证（拿播放地址的关键）
小程序的**视频**走抖音自研 TTNet 直连 socket —— 不理会系统 HTTP 代理、还做证书固定，
所以抓包抓不到。但**业务接口**走的是系统网络栈（抓包时能看到它们连到代理并握手失败，
正好暴露了这一点）。

进程内 hook `NSURLSession` / `AVFoundation`，读到的是**解密后的明文**，
证书固定完全不起作用。于是 `播放接口` 的响应 JSON（里面就有真正的 m3u8 / mp4 地址）
会被原样记录，包括完整 JSON body。

### 3. 把日志取回来
非越狱设备上抖音容器里的文件不好取，所以内置一个极小的 HTTP 服务，监听
`0.0.0.0:8899`：**同一 WiFi 下的电脑浏览器**打开 `http://<手机IP>:8899/` 即可看完整日志。
（抖音保持前台即可，日志是边跑边写的。）

---

## 编译

Windows 上编不了 iOS dylib（没有 clang / iPhoneOS SDK），走 GitHub 的 macOS runner：

```bash
export GITHUB_TOKEN=ghp_xxx        # 需要 scope: repo + workflow
python tools/build_remote.py
```

脚本会自动：建 public 仓库 → 推源码 → 触发 Actions → 等编译 → 把
`NoRecBypass.dylib` 拉到 `dist/`。

编译产物同时挂到 Release 的固定 tag `dylib-latest`，手机 Safari 直接点就能下载：
`https://github.com/jiayuLian/norec-bypass/releases/tag/dylib-latest`

> 仓库保持 **public**：public 仓库的 macOS runner 免费无限，private 要烧付费额度。

### 本地静态预检
没有编译器时先跑这几个（都能在 Windows 上跑）：

```bash
python <skill>/scripts/check_brackets.py  Tweak.m   # 括号 / @指令配对
python <skill>/scripts/scan_decls.py      Tweak.m   # 隐式声明 / 未定义 / 死代码
python <skill>/scripts/check_links.py     Tweak.m --workflow .github/workflows/build.yml
python <skill>/scripts/check_strings.py   Tweak.m   # 中文串里裸用 ASCII 双引号
python <skill>/scripts/check_overlay.py   Tweak.m   # 覆盖层窗口触摸陷阱
```

---

## 安装（TrollFools）

1. 手机 Safari 打开 Release 页，下载 `NoRecBypass.dylib`（落到「文件」App）
2. 打开 **TrollFools**（TrollStore 环境）
3. 找到 **抖音** → 注入 → 选刚下载的 `NoRecBypass.dylib`
4. 注入完成后**完全退出抖音**（上滑杀掉进程），再重新打开
5. 进「多来看点」小程序 → 开录屏 → 播放

---

## 验证

**功能性验证（最直接）**：开录屏后画面不再变黑、不再弹「温馨提示」，录屏能录到画面。

**日志验证**：电脑浏览器打开 `http://<手机IP>:8899/`，正常应看到：

```
[BOOT] NoRecBypass 1.0.1 · pid xxxx · 宿主 douyin
[BOOT] 日志文件 <路径>
[HOOK] -[UIScreen isCaptured] -> OK
[HOOK] -[UIScreen _isCaptured] -> OK / 不存在(跳过)
[HOOK] NSNotificationCenter 观察者过滤器 -> OK
[HOOK] NSURLSession dataTaskWithRequest:completionHandler: -> N 个类
[HOOK] AVFoundation(asset=1 item=1 player=1)
[HTTP] 已监听 0.0.0.0:8899
```

播放时出现的 `[HIT] -[UIScreen isCaptured] -> NO` 就是「抖音确实在查录屏、而它被我们骗了」
的直接证据；`[REQ]` / `[BODY]` 则是接口明文，里面能找到播放地址。

---

## 已知边界

- **只能拿到设备真正播放过的数据**。付费集如果服务端只下发 20 秒试看片段，客户端
  再怎么绕也拿不到完整流 —— 那是服务端行为，和录屏/抓包无关。
- `[BODY]` 只记 `text/json` 且 ≤512KB 的响应，最多 200 条，避免日志爆炸。
- 抖音有完整性校验的可能：注入后如果**启动即崩或功能异常**，说明它检测到了签名变化。
  此时可换思路（见下）。

---

## 版本

| 版本 | 说明 |
|---|---|
| 1.0.1 | isCaptured 绕过 + 通知观察者过滤 + NSURLSession/AV 明文取证 + 局域网日志服务 |
