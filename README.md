# V2EX 每日签到

私有仓库，通过 GitHub Actions 每天自动领取 V2EX 每日登录奖励。

## 组成

| 文件 | 作用 |
|---|---|
| `v2ex_auto.py` | 签到脚本。纯标准库实现，无第三方依赖 |
| `.github/workflows/checkin.yml` | 定时任务定义 |

## 运行时间

北京时间每天 **08:30**，**09:40** 再兜底跑一次。

V2EX 的每日奖励在早上 8 点之后才可领取，早于 8 点运行会返回「今天还没有奖励」。
第二次运行是幂等的：脚本先检查是否已领取，已领取则直接退出，不会重复请求。

## 需要的 Secrets

在 `Settings → Secrets and variables → Actions` 中配置两项：

| 名称 | 内容 |
|---|---|
| `V2EX_COOKIES` | 浏览器登录 v2ex.com 后，请求头里的完整 Cookie 字符串 |
| `V2EX_TOTP_SECRET` | 两步验证的 TOTP 密钥（Base32） |

`V2EX_TOTP_SECRET` 用于在 Actions 每次以新 IP 登录时自动通过 `/2fa` 校验。
若不配置，则仅当账号未开启两步验证时可用。

## 失效排查

| 日志报错 | 含义 | 处理 |
|---|---|---|
| 登录态无效 / Cookie 可能已经失效 | `A2` 过期 | 重新导出 Cookie，更新 `V2EX_COOKIES` |
| 两步验证未通过 | TOTP 密钥不匹配 | 重新绑定 2FA 并更新 `V2EX_TOTP_SECRET` |
| 签到请求失败 | Cloudflare 拦截或未到发奖时间 | 重跑一次；确认在 8 点后 |

改密码、在其它设备点「退出登录」都会让 `A2` 立即失效。

## 保活

GitHub 会在仓库连续 **60 天无提交**后自动停用定时任务，且不会发出任何通知。
收到保活提醒后，在本仓库任意提交一次（或手动 Run workflow）即可重置计时。
