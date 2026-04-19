# ruijie-sysu-go

一个基于 Go 实现的锐捷 802.1X / EAP-MD5 校园网认证工具，目标是做成可配置、可复用、便于二次适配的开源版本。

当前已在中山大学校园网环境完成自测。不同学校对 `identity`、附加字节、保活策略的要求可能不同，可能需要抓包确认。

## 为什么有这个项目

在进行有线连接校园网时，部分锐捷官方客户端在 Windows 11 下存在兼容性或可用性问题，无法稳定启动或完成认证。这个项目直接实现 EAPOL / EAP-MD5 认证流程，尽量减少对官方客户端的依赖。

参考项目：

- [sbwml/luci-app-mentohust](https://github.com/sbwml/luci-app-mentohust)

## 当前能力

- 支持发送 `EAPOL-Start`
- 支持处理 `Request/Identity`
- 支持处理 `Request/MD5-Challenge`
- 支持认证成功后的周期性保活
- 支持失败后自动重试
- 支持显式发送退出登录报文 `EAPOL-Logoff`
- 支持命令行、环境变量、JSON 配置文件三种配置方式
- 支持附加 `identity_suffix_hex`，方便适配部分校园网私有扩展

## 目录结构

```text
.
├── main.go
├── config.example.json
├── go.mod
└── README.md
```

## 运行前准备

### 1. 安装 Npcap

Windows 下抓取和发送 802.1X EAPOL 帧通常需要 [Npcap](https://npcap.com/)。

建议：

- 安装最新版 Npcap
- 允许 WinPcap API 兼容模式
- 使用管理员权限运行程序

### 2. 确认网卡设备名

先列出本机可用设备：

```bash
go run . -list
```

记录目标有线网卡对应的 `\Device\NPF_{...}` 名称，并确认该网卡的 MAC 地址。

## 配置方式

配置优先级如下：

```text
命令行参数 > 环境变量 > JSON 配置文件
```

### 方式一：配置文件

复制示例文件并填写：

```json
{
  "device_name": "\\Device\\NPF_{YOUR-DEVICE-ID}",
  "username": "your-username",
  "password": "your-password",
  "identity": "",
  "identity_suffix_hex": "",
  "local_mac": "12:34:56:78:9a:bc",
  "start_delay_ms": 0,
  "retry_delay_ms": 2000,
  "keepalive_sec": 30,
  "debug": false,
  "only_login": true
}
```

运行：

```bash
go run . -config config.json
```

### 方式二：环境变量

PowerShell 示例：

```powershell
$env:RUIJIE_DEVICE_NAME="\\Device\\NPF_{YOUR-DEVICE-ID}"
$env:RUIJIE_USERNAME="your-username"
$env:RUIJIE_PASSWORD="your-password"
$env:RUIJIE_LOCAL_MAC="12:34:56:78:9a:bc"
go run .
```

### 方式三：纯命令行

```bash
go run . ^
  -i "\\Device\\NPF_{YOUR-DEVICE-ID}" ^
  -u "your-username" ^
  -p "your-password" ^
  -m "12:34:56:78:9a:bc"
```

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `-config` | JSON 配置文件路径 |
| `-list` | 列出本机 pcap 设备 |
| `-i` | pcap 设备名 |
| `-u` | 认证用户名 |
| `-p` | 认证密码 |
| `-m` | 本机网卡 MAC 地址 |
| `-id` | 自定义 EAP Identity，默认等于用户名 |
| `-id-suffix-hex` | 在 identity 后追加十六进制字节 |
| `-start-delay-ms` | 首次发送 `EAPOL-Start` 前的延迟 |
| `-retry-delay-ms` | 认证失败后的重试延迟 |
| `-keepalive-sec` | 认证成功后重发 `EAPOL-Start` 的保活周期，`0` 表示关闭 |
| `-debug` | 输出调试日志 |
| `-l` | 认证成功后立即退出，默认 `true` |
| `-logout` / `-logoff` | 仅发送退出登录报文并退出 |

## 退出登录

如果当前网络环境支持 `EAPOL-Logoff`，可以使用下面的命令主动退出登录：

```bash
go run . -config config.json -logout
```

或：

```bash
go run . -i "\\Device\\NPF_{YOUR-DEVICE-ID}" -m "12:34:56:78:9a:bc" -logout
```

退出登录只依赖网卡设备名和本机 MAC，不要求再提供用户名和密码。

## 常见适配点

不同学校最常见的差异点通常在这里：

- `identity` 是否必须和用户名一致
- `identity_suffix_hex` 是否需要追加特定字节
- 是否需要持续保活
- 失败后的重试节奏是否要调整

如果你要适配新的学校，建议先抓取官方客户端或现有可用实现的认证过程，再对比：

- `Request/Identity` 的响应内容
- `Request/MD5-Challenge` 的用户名拼接方式
- 成功后的保活行为

## 已验证环境

- 中山大学校园网：可用

欢迎补充其它学校的兼容情况，但建议通过配置方式适配，不要把学校特定参数重新硬编码进主分支。

## 开发

### 构建

```bash
go build -o ruijie-go.exe .
```

### 自动发布

仓库包含 GitHub Actions 工作流：

- 推送 `v*` 标签时自动构建 Windows `amd64` 可执行文件
- 推荐使用 `RUIJIE_*` 环境变量，旧的 `RUNJIE_*` 前缀仍兼容
- 自动把构建产物上传到对应 GitHub Release
- 支持在 GitHub Actions 页面手动触发

### 格式化

```bash
gofmt -w main.go
```

## 安全提醒

- 不要把真实账号、密码、MAC 地址提交到仓库
- 建议把个人配置放到 `config.json` 或环境变量中，避免提交
- 本项目仅用于你有权接入的网络环境

## 后续建议

如果你准备继续把它做成更完整的通用工具，下一步比较值得做的是：

1. 增加多平台支持说明和测试矩阵
2. 增加“自动选择网卡 / 自动获取 MAC”能力
3. 把协议处理拆分成独立包，方便写单元测试
4. 加入抓包日志或十六进制调试输出落盘能力

## License

[MIT](./LICENSE)
