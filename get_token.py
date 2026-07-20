# -*- coding: utf-8 -*-
"""
塔斯汀 Token 自动获取脚本（本地运行）

原理：通过 WMPFDebugger 的 CDP 连接，触发小程序页面刷新，
     从网络请求头中截取当前有效的 user-token，
     再用 token 调接口获取 memberPhone。

前置条件：
  1. WMPFDebugger 已启动（frida hook 已加载，端口 62000 在监听）
  2. 塔斯汀小程序已打开

用法：
  pip install websocket-client
  python get_token.py

输出：
  TASTIN_USER_TOKEN=xxx
  TASTIN_MEMBER_PHONE=xxx
  把这两行更新到 GitHub Actions Secrets 即可。
"""

import json
import ssl
import sys
import time
import threading
import urllib.request

try:
    import websocket
except ImportError:
    print("[ERROR] 需要安装 websocket-client: pip install websocket-client")
    sys.exit(1)

# ============ 配置 ============
CDP_PORT = 62000
TASTIN_BASE = "https://sss-web.tastientech.com"
SHOP_ID = "28416"
VERSION = "3.78.0"
LISTEN_SECONDS = 10

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 "
    "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Windows WindowsWechat/WMPF "
    "WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541b36) XWEB/20089"
)
REFERER = "https://servicewechat.com/wx557473f23153a429/537/page-frame.html"


# ============ 第一步：通过 CDP 抓取 token ============
def capture_token_via_cdp():
    """连接 CDP proxy，触发页面刷新，从请求头中截取 user-token"""
    result = {"token": None, "phone": None}

    def on_message(ws, data):
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            return
        if msg.get("method") == "Network.requestWillBeSent":
            req = msg.get("params", {}).get("request", {})
            url = req.get("url", "")
            headers = req.get("headers", {})
            if "sss-web.tastientech.com" in url:
                token = headers.get("user-token", "")
                if token and not result["token"]:
                    result["token"] = token
                post_data = req.get("postData", "")
                if post_data and "memberPhone" in post_data:
                    try:
                        body = json.loads(post_data)
                        phone = body.get("memberPhone", "")
                        if phone and not result["phone"]:
                            result["phone"] = phone
                    except json.JSONDecodeError:
                        pass

    def on_open(ws):
        ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))

    def on_error(ws, error):
        print(f"[CDP] 错误: {error}")

    url = f"ws://127.0.0.1:{CDP_PORT}"
    ws = websocket.WebSocketApp(
        url, on_message=on_message, on_open=on_open, on_error=on_error
    )
    ws_thread = threading.Thread(target=ws.run_forever, daemon=True)
    ws_thread.start()

    # 等待连接建立并启用 Network
    time.sleep(2)
    # 触发页面刷新，让小程序重新发请求
    try:
        ws.send(json.dumps({"id": 2, "method": "Page.reload", "params": {}}))
    except Exception:
        pass

    # 等待捕获 token
    for _ in range(LISTEN_SECONDS * 2):
        if result["token"]:
            time.sleep(2)  # 多等一会看看能不能拿到 phone
            break
        time.sleep(0.5)

    ws.close()
    return result["token"], result["phone"]


# ============ 第二步：用 token 获取 memberPhone ============
def get_member_phone(token):
    """调用 getMemberDetail 接口获取加密手机号"""
    headers = {
        "Content-Type": "application/json",
        "user-token": token,
        "gray-shop-id": SHOP_ID,
        "channel": "1",
        "version": VERSION,
        "xweb_xhr": "1",
        "User-Agent": UA,
        "Referer": REFERER,
    }
    req = urllib.request.Request(
        TASTIN_BASE + "/api/intelligence/member/getMemberDetail/sign",
        headers=headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx) as resp:
            data = json.loads(resp.read().decode())
            if data.get("code") == 200 and data.get("result"):
                return (
                    data["result"].get("phone")
                    or data["result"].get("phoneEncrypted")
                )
    except Exception as e:
        print(f"[WARN] 获取 memberPhone 失败: {e}")
    return None


# ============ 第三步：验证 token 有效性 ============
def verify_token(token):
    """调一个简单接口验证 token 是否有效"""
    headers = {
        "Content-Type": "application/json",
        "user-token": token,
        "gray-shop-id": SHOP_ID,
        "channel": "1",
        "version": VERSION,
        "xweb_xhr": "1",
        "User-Agent": UA,
        "Referer": REFERER,
    }
    body = json.dumps({}).encode()
    req = urllib.request.Request(
        TASTIN_BASE + "/api/wx/point/myPoint",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx) as resp:
            data = json.loads(resp.read().decode())
            if data.get("code") == 200:
                point = data.get("result", {}).get("point", "?")
                print(f"[验证] token 有效，当前积分: {point}")
                return True
            else:
                print(f"[验证] token 无效: {data.get('msg')}")
                return False
    except Exception as e:
        print(f"[验证] 请求失败: {e}")
        return False


# ============ 主流程 ============
def main():
    print("=" * 50)
    print("  塔斯汀 Token 自动获取")
    print(f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    print()

    # 1. 通过 CDP 抓取 token
    print("[1/3] 通过 CDP 监听抓取 token（触发小程序页面刷新）...")
    token, phone = capture_token_via_cdp()

    if not token:
        print("\n[ERROR] 未能捕获到 token。请确认：")
        print("  1. WMPFDebugger 已启动（端口 62000 在监听）")
        print("  2. 塔斯汀小程序已打开")
        sys.exit(1)

    print(f"[1/3] 捕获到 token: {token}")

    # 2. 获取 memberPhone
    print("\n[2/3] 获取 memberPhone...")
    if not phone:
        phone = get_member_phone(token)
    if phone:
        print(f"[2/3] memberPhone: {phone}")
    else:
        print("[2/3] 未能获取 memberPhone（可沿用旧值）")

    # 3. 验证
    print("\n[3/3] 验证 token...")
    valid = verify_token(token)
    if not valid:
        print("[ERROR] token 验证失败，可能已过期")
        sys.exit(1)

    # 输出结果
    print("\n" + "=" * 50)
    print("  获取成功！请更新 GitHub Actions Secrets：")
    print("=" * 50)
    print()
    print(f"  TASTIN_USER_TOKEN={token}")
    if phone:
        print(f"  TASTIN_MEMBER_PHONE={phone}")
    print()
    print("  更新方式：GitHub 仓库 → Settings → Secrets and variables → Actions")
    print()


if __name__ == "__main__":
    main()
