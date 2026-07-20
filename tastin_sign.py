# -*- coding: utf-8 -*-
"""
塔斯汀小程序每日自动签到
用于 GitHub Actions 定时执行

环境变量配置（在 GitHub Settings > Secrets 中设置）：
  TASTIN_USER_TOKEN  - 用户认证 token（从抓包获取）
  TASTIN_MEMBER_PHONE - 加密手机号令牌（从抓包获取）
  TASTIN_SHOP_ID      - 门店 ID（默认 28416）
  TASTIN_VERSION      - 小程序版本号（默认 3.78.0）
  TASTIN_ACTIVITY_ID  - 可选，签到活动 ID 探测起点（默认 74，脚本会自动发现当月活动）

代理说明：
  塔斯汀 API 使用阿里云 WAF，会拦截海外数据中心 IP（如 GitHub Actions）。
  脚本会先尝试直连，若检测到 WAF 拦截（403/405），自动切换到国内免费代理重试。
  依赖：pip install pyfreeproxy（仅代理模式需要，本地直连无需安装）
"""

import json
import os
os.environ["TQDM_DISABLE"] = "1"  # 必须在 freeproxy import 之前，否则 tqdm 进度条无法抑制
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime
from zoneinfo import ZoneInfo

# 强制使用上海时区（GitHub Actions runner 默认 UTC）
_TZ_SHANGHAI = ZoneInfo("Asia/Shanghai")


def _now() -> datetime:
    """当前北京时间"""
    return datetime.now(_TZ_SHANGHAI)


# 是否在 GitHub Actions 环境中运行（Actions 的海外 IP 必定被 WAF 拦截，直接走代理）
_IN_ACTIONS = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

# GitHub Actions 环境证书链可能不完整，跳过验证
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# ============ 配置 ============
USER_TOKEN = os.environ.get("TASTIN_USER_TOKEN", "")
MEMBER_PHONE = os.environ.get("TASTIN_MEMBER_PHONE", "")
SHOP_ID = os.environ.get("TASTIN_SHOP_ID", "28416")
VERSION = os.environ.get("TASTIN_VERSION", "3.78.0")

# 邮件通知配置（可选，配置后 token 过期会发邮件提醒更新 Secret）
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_TO = os.environ.get("SMTP_TO", "")
# 签到结果也发邮件？设为 1 开启，默认只发 token 过期提醒
SMTP_NOTIFY_SIGN = os.environ.get("SMTP_NOTIFY_SIGN", "").lower() in ("1", "true", "yes")

BASE_URL = "https://sss-web.tastientech.com"

HEADERS = {
    "Content-Type": "application/json",
    "user-token": USER_TOKEN,
    "gray-shop-id": SHOP_ID,
    "channel": "1",
    "version": VERSION,
    "xweb_xhr": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 "
        "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
        "MiniProgramEnv/Windows WindowsWechat/WMPF "
        "WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541b36) XWEB/20089"
    ),
    "Referer": "https://servicewechat.com/wx557473f23153a429/537/page-frame.html",
}


# ============ 请求工具（直连 + 代理回退） ============
_proxy_client = None
_waf_blocked = False


def _is_waf_response(result: dict) -> bool:
    """检测阿里云 WAF 拦截（返回 HTML 而非 JSON，或 403/405）"""
    code = result.get("code")
    msg = str(result.get("msg", ""))
    if code in (403, 405):
        return True
    if "<!doctype" in msg.lower() or "<html" in msg.lower():
        return True
    return False


def _direct_request(method: str, path: str, body: dict | None = None) -> dict:
    """直连请求（urllib，无额外依赖）"""
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace") if e.fp else ""
        return {"code": e.code, "msg": f"HTTP {e.code}: {body_text[:200]}", "result": None}
    except Exception as e:
        return {"code": -1, "msg": str(e), "result": None}


def _get_proxy_client():
    """懒初始化 freeproxy 代理客户端（仅国内 IP）"""
    global _proxy_client
    if _proxy_client is None:
        try:
            from freeproxy.freeproxy import ProxiedSessionClient
        except ImportError:
            print("[proxy] 错误：未安装 pyfreeproxy，无法使用代理模式")
            print("[proxy] 请运行: pip install pyfreeproxy")
            sys.exit(1)

        # 抑制 requests 的 SSL 警告
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass

        # 抑制 tqdm 进度条和 freeproxy WARNING 日志
        import logging
        logging.getLogger("freeproxy").setLevel(logging.ERROR)

        print("[proxy] 正在获取国内免费代理...")
        _proxy_client = ProxiedSessionClient(
            proxy_sources=[
                "KuaidailiProxiedSession",
                "QiyunipProxiedSession",
                "KxdailiProxiedSession",
                "IP89ProxiedSession",
                "GoodIPSProxiedSession",
                "TheSpeedXProxiedSession",
            ],
            init_proxied_session_cfg={
                "max_pages": 1,
                "filter_rule": {
                    "country_code": ["CN"],
                    "protocol": ["http", "https"],
                },
            },
            disable_print=True,
            max_tries=15,
        )
        print("[proxy] 代理池初始化完成")
    return _proxy_client


def _proxy_request(method: str, path: str, body: dict | None = None) -> dict:
    """通过国内代理发送请求（静默重试 3 次，每次间隔 3s 等待代理源刷新）"""
    import time
    client = _get_proxy_client()
    url = BASE_URL + path
    last_err = {"code": -1, "msg": "proxy: all attempts failed", "result": None}
    for attempt in range(3):
        try:
            if method.upper() == "POST":
                resp = client.post(url, headers=HEADERS, json=body, timeout=15, verify=False)
            else:
                resp = client.get(url, headers=HEADERS, timeout=15, verify=False)
            result = resp.json()
            if result.get("code") != -1:
                return result
            last_err = result
        except Exception as e:
            last_err = {"code": -1, "msg": f"proxy error: {e}", "result": None}
        if attempt < 2:
            print(f"[proxy] 请求失败，{3}s 后重试 ({attempt+1}/3)...")
            time.sleep(3)
    return last_err


def api_request(method: str, path: str, body: dict | None = None) -> dict:
    """统一请求入口：Actions 环境直接走代理；本地先直连，遇 WAF 再回退代理"""
    global _waf_blocked

    if _waf_blocked or _IN_ACTIONS:
        if not _waf_blocked:
            print("[proxy] GitHub Actions 环境，直接使用国内代理...")
            _waf_blocked = True
        return _proxy_request(method, path, body)

    result = _direct_request(method, path, body)
    if _is_waf_response(result):
        print("[proxy] 检测到 WAF 拦截（海外 IP 被拒），切换到国内代理...")
        _waf_blocked = True
        return _proxy_request(method, path, body)
    return result


# ============ 邮件通知 ============
def send_email(subject: str, body_html: str):
    """发送邮件通知（未配置 SMTP 时静默跳过）"""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        return
    to_addr = SMTP_TO or SMTP_USER
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.header import Header

        msg = MIMEText(body_html, "html", "utf-8")
        msg["From"] = f"塔斯汀签到 <{SMTP_USER}>"
        msg["To"] = to_addr
        msg["Subject"] = Header(subject, "utf-8")

        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            try:
                server.starttls()
            except Exception:
                pass

        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [to_addr], msg.as_string())
        server.quit()
        print(f"[notify] 邮件已发送至 {to_addr}")
    except Exception as e:
        print(f"[notify] 邮件发送失败: {e}")


# ============ 自动发现签到活动 ID ============
def discover_activity_id() -> int:
    """自动获取当前有效的签到活动 ID，无需硬编码"""
    import time as _time

    # 方法1：从积分商城 banner 列表中找 jumpCode=SIGN 的入口
    res = api_request("POST", "/api/minic/shop/intelligence/banner/c/list/sign", {
        "shopId": int(SHOP_ID), "birthday": "", "gender": 0,
        "nickName": None, "phone": MEMBER_PHONE,
    })
    if res.get("code") == 200 and res.get("result"):
        for item in res["result"]:
            if item.get("jumpCode") == "SIGN":
                try:
                    para = json.loads(item.get("jumpPara", "{}"))
                    aid = para.get("activityId")
                    if aid:
                        print(f"[discover] 从 banner 获取到签到活动 ID: {aid} ({item.get('bannerName', '')})")
                        return int(aid)
                except (json.JSONDecodeError, TypeError):
                    pass

    # 方法2：从上次已知的 ID 开始向上探测，找到时间范围覆盖当前的活动
    now_ms = int(_time.time() * 1000)
    start_probe = int(os.environ.get("TASTIN_ACTIVITY_ID", "74"))
    for aid in range(start_probe, start_probe + 30):
        r = api_request("POST", "/api/sign/member/signInfoV2", {"activityId": aid})
        if r.get("code") == 200 and r.get("result"):
            info = r["result"].get("activityInfo", {})
            st = info.get("startTime", 0)
            et = info.get("endTime", 0)
            if st <= now_ms <= et:
                print(f"[discover] 探测到当前有效签到活动: ID={aid} ({info.get('name', '')})")
                return aid

    # 兜底：用环境变量或默认值
    fallback = int(os.environ.get("TASTIN_ACTIVITY_ID", "74"))
    print(f"[discover] 未能自动发现，使用默认值: {fallback}")
    return fallback


# ============ 业务逻辑 ============
def check_token() -> bool:
    """验证 token 是否有效"""
    res = api_request("POST", "/api/wx/point/myPoint", {})
    if res.get("code") == 200:
        point = res.get("result", {}).get("point", "?")
        print(f"[check] token 有效，当前积分: {point}")
        return True
    print(f"[check] token 无效或已过期: {res.get('msg')}")
    return False


def get_sign_info(activity_id: int) -> dict | None:
    """查询签到活动状态"""
    res = api_request("POST", "/api/sign/member/signInfoV2", {"activityId": activity_id})
    if res.get("code") != 200 or not res.get("result"):
        print(f"[info] 查询签到信息失败: {res.get('msg')}")
        return None
    return res["result"]


def do_sign(activity_id: int) -> dict:
    """执行签到"""
    res = api_request("POST", "/api/sign/member/signV2/sign", {
        "activityId": activity_id,
        "memberName": "",
        "memberPhone": MEMBER_PHONE,
    })
    return res


def format_reward(result: dict) -> str:
    """格式化奖励信息"""
    lines = []
    lines.append(f"连续签到: {result.get('continuousNum', '?')} 天")
    for reward in result.get("rewardInfoList") or []:
        lines.append(f"  奖励: {reward.get('rewardName', '未知')}")
        for coupon in reward.get("couponInfo") or []:
            lines.append(f"    - {coupon.get('name')} ({coupon.get('couponContent')}, {coupon.get('couponTime')})")
        if reward.get("point", 0) > 0:
            lines.append(f"    - 积分 +{reward['point']}")
    return "\n".join(lines)


# ============ 主流程 ============
def main():
    print()
    print("===================================================================")
    print(f"🍔 塔斯汀每日自动签到")
    print(f"👨‍💻 Author: LeapYa")
    print(f"🔗 GitHub: https://github.com/LeapYa/tastin-sign")
    print(f"⏰ {_now().strftime('%Y-%m-%d %H:%M:%S')} (Asia/Shanghai)")
    print("===================================================================")
    print()

    # 0. 检查配置
    if not USER_TOKEN or not MEMBER_PHONE:
        print("\n[ERROR] 缺少环境变量 TASTIN_USER_TOKEN 或 TASTIN_MEMBER_PHONE")
        print("请在 GitHub Settings > Secrets and variables > Actions 中配置")
        sys.exit(1)

    # 1. 验证 token
    print()
    if not check_token():
        print("\n[ERROR] token 已失效，请重新抓包获取新 token 并更新 GitHub Secrets")
        print("::error::塔斯汀 token 已过期，需要手动更新！")
        send_email(
            "⚠️ 塔斯汀签到 Token 已过期",
            "<h3>塔斯汀签到 Token 已失效</h3>"
            "<p>请重新运行 <code>get_token.py</code> 获取新 token，"
            "然后更新 GitHub 仓库的 Secrets：</p>"
            "<ul><li>TASTIN_USER_TOKEN</li><li>TASTIN_MEMBER_PHONE</li></ul>"
            f"<p><small>时间: {_now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>",
        )
        sys.exit(1)

    # 2. 自动发现当前签到活动 ID
    print()
    activity_id = discover_activity_id()

    # 3. 查询签到状态
    print()
    info = get_sign_info(activity_id)
    if info:
        act = info.get("activityInfo", {})
        print(f"[info] 活动: {act.get('name', '未知')}")
        print(f"[info] 每日签到: {'开启' if act.get('daySignOpen') else '关闭'}")

    # 4. 执行签到
    print()
    res = do_sign(activity_id)
    sign_ok = False
    sign_msg = ""
    if res.get("code") == 200 and res.get("result"):
        print("[sign] 签到成功!")
        reward_text = format_reward(res["result"])
        print(reward_text)
        sign_ok = True
        sign_msg = f"签到成功！连续 {res['result'].get('continuousNum', '?')} 天"
    elif res.get("msg") and ("签过" in res["msg"] or "已签" in res["msg"]):
        print(f"[sign] 今天已经签过了: {res['msg']}")
        sign_ok = True
        sign_msg = "今天已经签过了"
    else:
        sign_msg = res.get("msg", "未知错误")
        print(f"[sign] 签到失败: {sign_msg}")
        print("::error::签到失败，请检查日志")
        if SMTP_NOTIFY_SIGN:
            send_email(
                "❌ 塔斯汀签到失败",
                f"<h3>塔斯汀签到失败</h3><p>错误信息: {sign_msg}</p>"
                f"<p><small>时间: {_now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>",
            )
        sys.exit(1)

    # 5. 最终积分
    print()
    point_text = ""
    final = api_request("POST", "/api/wx/point/myPoint", {})
    if final.get("code") == 200 and final.get("result"):
        point_text = f"当前积分: {final['result'].get('point', '?')}"
        print(f"[done] {point_text}")

    print("\n[done] 签到流程完成")

    # 6. 发送成功通知（仅在开启 SMTP_NOTIFY_SIGN 时）
    if SMTP_NOTIFY_SIGN:
        send_email(
            "✅ 塔斯汀签到成功",
            f"<h3>塔斯汀每日签到</h3>"
            f"<p><b>{sign_msg}</b></p>"
            f"<p>{point_text}</p>"
            f"<p><small>时间: {_now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>",
        )


if __name__ == "__main__":
    main()
