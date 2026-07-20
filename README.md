# 塔斯汀每日自动签到

**🍔 微信小程序逆向 + GitHub Actions，每天自动签到白嫖优惠券**

学校塔斯汀不让用团购，只能小程序点单。好在签到活动连续 7 天给 0 元券，但手动签太容易忘。于是逆向了小程序接口，写了这个自动签到脚本。

**特色功能：**

1. ✅ GitHub Actions 定时执行 —— 免费、免服务器，每天 9:05 自动签到
2. ✅ 活动 ID 自动发现 —— 跨月无需手动更新，脚本自动获取当月签到活动
3. ✅ 国内代理绕过 WAF —— 阿里云 WAF 拦截海外 IP？自动切换国内免费代理
4. ✅ 邮件通知 —— Token 过期自动发邮件提醒，不怕断签
5. ✅ 一键获取 Token —— 本地运行 `get_token.py`，CDP 被动截取，无需手动抓包

## 原理

通过 WMPFDebugger + Frida hook 微信小程序运行时，利用 CDP（Chrome DevTools Protocol）监听网络请求，截取认证 token，然后模拟小程序请求完成签到。

## WAF 绕过

塔斯汀 API 使用阿里云 WAF，会拦截海外数据中心 IP（GitHub Actions 的 runner 在海外）。脚本内置了自动代理回退：

1. 先尝试直连（本地运行时通常成功）
2. 如果收到 403/405（WAF 拦截），自动切换到国内免费代理重试
3. 代理来源：[pyfreeproxy](https://github.com/CharlesPikachu/freeproxy)，筛选中国大陆 HTTP/HTTPS 代理

本地运行无需安装额外依赖（直连即可）。GitHub Actions 中会自动 `pip install pyfreeproxy`。

## 系统要求

**仅支持 Windows。** WMPFDebugger 通过 Frida attach 到 `WeChatAppEx.exe` 进程实现 hook，这是 Windows 微信电脑版独有的小程序运行时进程。Linux 和 macOS 的微信没有这个进程，无法使用本方案。

获取 token 需要在 Windows 本地完成，签到脚本本身通过 GitHub Actions（Ubuntu）运行，不受平台限制。

## 文件说明

| 文件 | 用途 |
|------|------|
| `tastin_sign.py` | 签到脚本，在 GitHub Actions 中运行 |
| `get_token.py` | 本地运行（Windows），自动获取/刷新 token |
| `.github/workflows/tastin_sign.yml` | Actions 定时任务配置 |

## 环境准备（Windows）

以下命令均在 **PowerShell** 中执行（Windows 10/11 自带，Win+X → Windows PowerShell）。

### 1. 安装 Node.js（≥ v22 LTS）

从 https://nodejs.org 下载安装包，双击安装，安装完成后验证：

```powershell
node --version   # 需要 >= 22.x
```

### 2. 安装 yarn

```powershell
npm install -g yarn
```

### 3. 安装 Git（如未安装）

从 https://git-scm.com/download/win 下载安装。安装时勾选 "Add to PATH"。

### 4. 下载 WMPFDebugger

```powershell
git clone https://github.com/evi0s/WMPFDebugger.git
cd WMPFDebugger
```

> **国内网络问题：** 如果 clone 很慢或超时，用浏览器打开下面的链接下载 zip，手动解压：
> ```
> https://gh-proxy.com/https://github.com/evi0s/WMPFDebugger/archive/refs/heads/main.zip
> ```
> 解压后将 `WMPFDebugger-main` 文件夹重命名为 `WMPFDebugger`，然后 `cd WMPFDebugger`。

### 5. 安装项目依赖（重点，有坑）

直接 `yarn install` 会因为 frida 的 prebuild 二进制下载超时而失败（国内网络无法访问 GitHub Release）。需要手动处理：

```powershell
# 第一步：跳过脚本安装依赖
yarn install --ignore-scripts --registry https://registry.npmmirror.com
```

```powershell
# 第二步：查看你的 Node ABI 版本
node -p "process.versions.modules"
# 输出示例：137（Node 24 对应 137）
```

```powershell
# 第三步：下载 frida prebuild 二进制
# 以 frida 17.3.2 + win32-x64 为例，用浏览器或 curl.exe 下载：
curl.exe -L -o frida-prebuild.tar.gz "https://gh-proxy.com/https://github.com/frida/frida/releases/download/17.3.2/frida-v17.3.2-napi-v8-win32-x64.tar.gz"
```

> **注意：** PowerShell 5 中 `curl` 是 `Invoke-WebRequest` 的别名，参数不兼容。必须用 `curl.exe`（Windows 10 1803+ 自带）或者直接用浏览器下载。

```powershell
# 第四步：解压到 frida 的 build 目录
# Windows 10 1803+ 自带 tar 命令
cd node_modules\frida
mkdir build
tar -xzf ..\..\frida-prebuild.tar.gz -C build --strip-components=1
cd ..\..
```

> 如果你的 Windows 版本较老没有 `tar` 命令，可以用 [7-Zip](https://7-zip.org) 手动解压 `frida-prebuild.tar.gz`，将里面的文件（`frida_binding.node` 等）放到 `node_modules\frida\build\` 目录下。

```powershell
# 第五步：验证 frida 能正常加载
node -e "const frida = require('frida'); console.log('frida OK')"
```

> **注意：** 如果 `yarn install` 报 "Visual Studio is not installed"，说明 frida 在尝试从源码编译。确保你用了 `--ignore-scripts` 并手动放置了 prebuild 二进制。

### 6. 补充 WMPF 版本配置

WMPFDebugger 需要与你微信版本对应的偏移配置文件。**没有对应版本的配置，WMPFDebugger 就无法调试小程序。**

查看你的 WMPF 版本：打开任务管理器 → 找到 `WeChatAppEx.exe` → 展开 → 右键 → 打开文件所在的位置。你会进入类似这样的目录：

```
C:\Users\用户名\AppData\Roaming\Tencent\xwechat\XPlugin\plugins\RadiumWMPF\20089\extracted\runtime
```

路径中的 `20089` 就是你的 WMPF 版本（即小程序运行时版本）。

检查 `frida\config\` 目录下是否有 `addresses.20089.json`。如果没有：

- 去 [WMPFDebugger Issues/PRs](https://github.com/evi0s/WMPFDebugger/pulls) 搜索你的版本号，看是否有人提交了配置
- 如果找不到，需要自己逆向 `flue.dll` 获取偏移地址（参考项目 README）

以 20089 为例，创建 `frida\config\addresses.20089.json`：

```json
{
    "Version": 20089,
    "LoadStartHookOffset": "0x25E0170",
    "CDPFilterHookOffset": "0x30CF8F0",
    "SceneOffsets": [64, 1480, 8, 1416, 16, 456]
}
```

### 7. 启动 WMPFDebugger

```powershell
npx ts-node src/index.ts
```

看到以下输出说明成功：

```
[server] debug server running on ws://localhost:9421
[server] proxy server running on ws://localhost:62000
[frida] script loaded, WMPF version: 20089, pid: xxxx
[frida] you can now open any miniapps
```

> **重要：** 必须在启动 WMPFDebugger **之后**再打开小程序，hook 只对新打开的小程序生效。如果之前已经打开了，需要关闭后重新进入。

### 8. 连接 DevTools（可选，用于调试）

在 Chrome 地址栏**手动输入**（无法通过命令行或脚本打开）：

```
devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
```

## 获取 Token

确保 WMPFDebugger 已启动且塔斯汀小程序已打开，然后：

```powershell
pip install websocket-client
python get_token.py
```

脚本会自动触发小程序页面刷新，从网络请求中截取 `user-token` 和 `memberPhone`，输出类似：

```
TASTIN_USER_TOKEN=sssfeb3b700-xxxx-xxxx-xxxx-xxxxxxxxxxxx
TASTIN_MEMBER_PHONE=p6ewdvwrsHXrebZASMpUYw==
```

## 配置 GitHub Actions

### 1. 推送本仓库到 GitHub

```powershell
git remote add origin https://github.com/YOUR_USERNAME/tastin-sign.git
git branch -M main
git push -u origin main
```

### 2. 配置 Secrets

在仓库 Settings → Secrets and variables → Actions 中添加：

| Secret 名称 | 必填 | 说明 |
|-------------|------|------|
| `TASTIN_USER_TOKEN` | 是 | 认证 token |
| `TASTIN_MEMBER_PHONE` | 是 | 加密手机号令牌 |
| `SMTP_HOST` | 否 | SMTP 服务器，如 `smtp.qq.com` |
| `SMTP_PORT` | 否 | 默认 465 |
| `SMTP_USER` | 否 | 发件邮箱 |
| `SMTP_PASS` | 否 | 邮箱授权码 |
| `SMTP_TO` | 否 | 收件邮箱（不填发给自己） |
| `SMTP_NOTIFY_SIGN` | 否 | 设为 `1` 则签到结果也发邮件，默认只发 token 过期提醒 |

### 3. 自动执行

推送后 Actions 会在每天早上 9:05（北京时间）自动执行，也可以在 Actions 页面手动触发。

## Token 过期

Token 有效期取决于服务端策略。过期后：

- Actions 日志会输出 `::error::` 高亮提醒
- 如果配置了 SMTP，会收到邮件通知
- 重新运行 `python get_token.py` 获取新 token，更新 Secrets 即可

## 常见问题

**Q: frida 安装报 "Visual Studio is not installed"**
A: 不要让它从源码编译。用 `yarn install --ignore-scripts` 跳过，然后手动下载 prebuild 二进制放到 `node_modules\frida\build\` 目录。

**Q: 启动报 "version config not found: xxxxx"**
A: 你的 WMPF 版本没有对应的偏移配置文件。去项目 PRs 里找，或者自己逆向。

**Q: DevTools 打不开 / 白屏**
A: `devtools://` 协议只能在 Chrome 地址栏手动输入，不能通过命令行 `start` 或脚本打开。

**Q: 小程序打开了但抓不到请求**
A: 确保先启动 WMPFDebugger 再打开小程序。已经打开的小程序不会被 hook，需要关闭后重新进入。

**Q: 国内 clone GitHub 太慢**
A: 用 `https://gh-proxy.com/` 前缀下载 zip 包，或者配置代理。

**Q: PowerShell 里 `curl` 报错 / 参数不对**
A: PowerShell 5 的 `curl` 是 `Invoke-WebRequest` 的别名，和 Linux 的 curl 完全不同。请用 `curl.exe`（带 `.exe` 后缀）调用 Windows 自带的真正 curl。

**Q: 没有 `tar` 命令**
A: Windows 10 1803（2018年4月更新）及以上版本自带 `tar.exe`。如果你的系统更老，用 7-Zip 手动解压 `.tar.gz` 文件即可。

**Q: Actions 日志显示 HTTP 405 / HTML 页面**
A: 这是阿里云 WAF 拦截了 GitHub Actions 的海外 IP。脚本已内置代理回退，会自动切换到国内代理重试。如果代理也全部失败，可能是免费代理源暂时不可用，等下次定时执行通常能恢复。

**Q: 代理模式报错 "未安装 pyfreeproxy"**
A: 本地运行时如果直连成功则不需要代理。如果你本地也被 WAF 拦截（比如用了海外 VPS），运行 `pip install pyfreeproxy` 即可。

## 免责声明

本项目仅供学习交流使用，请勿用于商业用途或违反平台规则。使用本项目产生的一切后果由使用者自行承担。

## License

[MIT](LICENSE)
