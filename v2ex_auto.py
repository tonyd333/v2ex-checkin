#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V2EX 每日登录奖励签到，支持 TOTP 两步验证自动通过。

只依赖 Python 标准库。三个关键实现细节（均为实测所得）：

  1. 必须用 CookieJar 保存 Set-Cookie。两步验证通过后 V2EX 会下发新的
     A2O 等 cookie，若每次请求都手写固定 Cookie 头，跟随跳转时会丢失
     会话状态，表现为「验证码被拒」并弹回 /2fa。
  2. 提交 /2fa 必须带 Origin 与 Referer，否则服务器忽略提交、原样重渲染
     表单，且不返回任何错误提示。
  3. 提交表单时只发最小头集。携带 sec-fetch-site: none 这类页面导航头
     同样会导致提交被忽略。

环境变量：
  V2EX_COOKIES       必填，浏览器 Cookie 请求头整段
  V2EX_TOTP_SECRET   可选，两步验证的 Base32 密钥
"""

import base64
import hashlib
import hmac
import http.cookiejar
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://www.v2ex.com"
NEEDED_KEYS = ("PB3_SESSION", "A2", "V2EX_LANG", "V2EX_TAB")
TIMEOUT = 20

HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "referer": "https://www.v2ex.com/",
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
}

msg = []


def add(name, value):
    msg.append({"name": name, "value": value})
    print(f"{name}: {value}")


def parse_cookies(raw):
    """把 Cookie 请求头解析为 dict，值去掉外层引号。"""
    out = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        if name in NEEDED_KEYS:
            out[name] = value.strip().strip('"')
    return out


def build_opener(cookies):
    """带 CookieJar 的 opener：服务端 Set-Cookie 会被自动保存并回传。"""
    proxies = {}
    for scheme, names in (
        ("http", ("HTTP_PROXY", "http_proxy")),
        ("https", ("HTTPS_PROXY", "https_proxy")),
    ):
        for name in names:
            value = os.environ.get(name)
            if value:
                proxies[scheme] = value
                break

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPCookieProcessor(jar),
    )
    for name, value in cookies.items():
        jar.set_cookie(
            http.cookiejar.Cookie(
                0, name, value, None, False,
                "www.v2ex.com", True, False,
                "/", True, False,
                None, False, None, None, {}, False,
            )
        )
    return opener


def fetch(opener, url, data=None, extra=None, minimal=False):
    """返回 (最终URL, 响应文本, 状态码)。4xx/5xx 也尽量取回正文。"""
    if minimal:
        headers = {
            "user-agent": HEADERS["user-agent"],
            "accept": "text/html,application/xhtml+xml",
            "accept-language": HEADERS["accept-language"],
            "content-type": "application/x-www-form-urlencoded",
        }
    else:
        headers = dict(HEADERS)
    if extra:
        headers.update(extra)
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with opener.open(request, timeout=TIMEOUT) as resp:
            return resp.geturl(), resp.read().decode("utf-8", "ignore"), resp.status
    except urllib.error.HTTPError as exc:
        return exc.geturl(), exc.read().decode("utf-8", "ignore"), exc.code


def totp_code(secret, step_offset=0):
    """标准 TOTP：SHA1 / 30 秒 / 6 位。"""
    normalized = secret.strip().replace(" ", "").replace("-", "").upper()
    pad = (8 - len(normalized) % 8) % 8
    key = base64.b32decode(normalized + "=" * pad)
    counter = int(time.time()) // 30 + step_offset
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1000000:06d}"


def extract_hidden(html, field):
    for pattern in (
        rf'name="{field}"[^>]*value="([^"]+)"',
        rf'value="([^"]+)"[^>]*name="{field}"',
    ):
        found = re.search(pattern, html)
        if found:
            return found.group(1)
    return None


def is_2fa(url, html):
    return "/2fa" in url or "otp_code" in html


def solve_2fa(opener, url, html, secret):
    once = extract_hidden(html, "once")
    if not once:
        return False, "无法从两步验证页面提取 once 令牌"

    for attempt in range(2):
        code = totp_code(secret, attempt)
        try:
            new_url, new_html, _ = fetch(
                opener,
                f"{BASE}/2fa",
                data={"code": code, "once": once},
                extra={"origin": BASE, "referer": f"{BASE}/2fa"},
                minimal=True,
            )
        except Exception as exc:
            return False, f"提交验证码时请求异常（{type(exc).__name__}）"
        if not is_2fa(new_url, new_html):
            return True, ""
        if attempt == 0:
            time.sleep(2)
    return False, "验证码被拒绝，请检查 TOTP 密钥与设备时间"


def beijing_now():
    """返回北京时间的 struct_time，不依赖 runner 的系统时区。

    GitHub 的 runner 默认是 UTC，虽然 workflow 里用 timedatectl 改过，
    但这里显式换算，避免因时区设置顺序变化而误判。
    """
    return time.gmtime(time.time() + 8 * 3600)


def main():
    # 时段保护：V2EX 在早上 8 点之后才发当日奖励。
    # GitHub 的 schedule 可能延迟数小时，若把本应白天的运行推到了次日凌晨，
    # 强行请求得到的是「今日奖励尚未开放」而不是错误。这种情况下应当跳过，
    # 而不是让断言把它判定为签到失败（否则会产生一次无意义的红色告警）。
    now = beijing_now()
    if now.tm_hour < 8:
        add("运行信息", f"北京时间 {now.tm_hour:02d}:{now.tm_min:02d}，未到发奖时段，跳过本次运行")
        return

    raw = os.environ.get("V2EX_COOKIES", "").strip()
    secret = os.environ.get("V2EX_TOTP_SECRET", "").strip()

    if not raw:
        add("登录信息", "未配置 V2EX_COOKIES")
        return

    cookies = parse_cookies(raw)
    if "A2" not in cookies:
        add("登录信息", "Cookie 中没有 A2，请重新导出完整的请求头 Cookie")
        return

    opener = build_opener(cookies)

    try:
        url, html, _ = fetch(opener, f"{BASE}/mission/daily")
    except Exception as exc:
        add("登录信息", f"无法连接网站（{type(exc).__name__}）")
        return

    if is_2fa(url, html):
        if not secret:
            add("登录信息", "需要两步验证，但未配置 V2EX_TOTP_SECRET")
            return
        ok, err = solve_2fa(opener, url, html, secret)
        if not ok:
            add("登录信息", f"两步验证失败（{err}）")
            return
        add("登录信息", "两步验证通过")
        try:
            url, html, _ = fetch(opener, f"{BASE}/mission/daily")
        except Exception as exc:
            add("登录信息", f"无法连接网站（{type(exc).__name__}）")
            return

    if "/signin" in url or "你要查看的页面需要先登录" in html:
        add("登录信息", "登录失败，Cookie 可能已经失效")
        return

    if "每日登录奖励已领取" in html:
        # 无论是否已输出「两步验证通过」，都要给出一行可被断言识别的状态
        if not any(item["name"] == "签到信息" for item in msg):
            add("签到信息", "今日已签到，无需重复签到")
        streak = re.search(r"已连续登录 (\d+) 天", html)
        if streak:
            add("累计登录", f"{streak.group(1)} 天")
        return

    token = re.search(r"/mission/daily/redeem\?once=(\d+)", html)
    if not token:
        add("登录信息", "无法获取 once 参数，页面结构可能已变更")
        return

    once = token.group(1)
    add("登录信息", "登录成功")

    try:
        _, redeem_html, _ = fetch(opener, f"{BASE}/mission/daily/redeem?once={once}")
    except Exception as exc:
        add("签到信息", f"签到失败，领取请求异常（{type(exc).__name__}）")
        return

    reward = re.search(r"已成功领取每日登录奖励 (\d+) 铜币", redeem_html)
    if reward:
        add("签到信息", f"签到成功，获得 {reward.group(1)} 铜币")
        return

    if "每日登录奖励已领取" in redeem_html:
        add("签到信息", "今日已签到，无需重复签到")
        return

    # 领取请求可能被拦截但奖励已到账，回查任务页确认
    try:
        _, recheck_html, _ = fetch(opener, f"{BASE}/mission/daily")
    except Exception:
        recheck_html = ""

    if "每日登录奖励已领取" in recheck_html:
        add("签到信息", "今日已签到")
    else:
        add("签到信息", "签到失败，未能确认领取结果")


if __name__ == "__main__":
    print(" V2EX 签到开始 ".center(60, "="))
    try:
        main()
    except Exception as exc:
        print(f"登录信息: 脚本异常（{type(exc).__name__}: {exc}）")
    print(" V2EX 签到结束 ".center(60, "="))
    sys.exit(0)
