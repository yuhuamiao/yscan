# yscan

**轻量化 CAASM（Cyber Asset Attack Surface Management）系统**

`yscan` 是一个以 Go 实现、面向企业内网的资产持续发现与风险验证工具。它以单机部署和 SQLite 状态模型为基础，把网段发现、端口与服务画像、增量变化跟踪、定向漏洞验证和轻 Web 控制台连接为一条可持续运行的闭环。

> 当前 v1 聚焦经授权的企业内网环境。域名收集能力保留用于授权测试与资产核验，但本项目不提供互联网测绘、未授权扫描或重型安全运营平台能力。

## 为什么是 yscan

企业内网资产清单常常滞后于真实网络：临时主机、新开端口、暴露的中间件和遗留服务不会自动出现在 CMDB 中。`yscan` 从 CIDR 或明确目标出发，持续记录资产状态，而不是每次只输出一份临时扫描结果。

它的轻量化不是功能缩水，而是明确的工程取舍：

- **部署轻**：单个 Go 二进制和 SQLite 即可运行，不要求 Kafka、ES、Redis、Kubernetes 或消息总线。
- **接入轻**：不依赖 CMDB、SOC、EDR、ITSM 等前置对接；给定 CIDR 即可发起首轮巡检。
- **使用轻**：CLI、HTTP API 和浏览器控制台共享同一任务、资产与报告数据。
- **运维轻**：状态数据落在本地 SQLite，扫描结果和 Markdown 报告可直接审计与备份。
- **验证轻**：先缩小到真实存活资产和已识别服务，再调用本地 Nuclei 做定向验证。
- **界面轻**：控制台只覆盖任务、资产、变化、漏洞与报告，不引入 RBAC、工单、多租户或大屏等重型平台模块。

## 当前能力

| 能力 | 当前实现 | 说明 |
| --- | --- | --- |
| 内网资产发现 | IPv4 CIDR 展开、ICMP/TCP 存活探测 | 网段任务有主机数量上限，并支持任务取消与进度更新 |
| 服务画像 | 内网基线端口、Banner 读取、基础规则匹配 | 覆盖 SMB、RDP、LDAP、WinRM、常见数据库、Docker、Kubernetes、Elasticsearch 等常见暴露面 |
| 资产状态管理 | SQLite 主机与端口库存 | 记录 `first_seen`、`last_seen`、`is_active`，并生成主机/端口增量变化 |
| 漏洞验证 | 本地 [Nuclei](https://github.com/projectdiscovery/nuclei) 调用与 JSONL 解析 | 使用本地 templates，网段任务按 v1 静态服务标签选择模板 tags |
| 域名资产收集 | crt.sh、搜索引擎、DNS 字典爆破、DNS 活性验证 | 支持 `internal`、`external`、`hybrid` DNS 策略，以及泛解析/CNAME 聚合干扰处理 |
| 报告 | Markdown 任务报告 | 每个成功任务生成 `reports/task-<id>.md` |
| 接口与控制台 | HTTP API + 轻 Web 控制台 | 支持任务创建、取消、资产详情、变化、漏洞和报告查看 |

## 架构

```text
CLI / HTTP API / Web Console
            |
       Task Orchestrator
            |
  +---------+----------+
  |                    |
Subnet workflow     Domain workflow
  |                    |
Host discovery      Passive / active discovery
  |                    |
Quick port profile  DNS validation and filtering
  |                    |
Service and banner identification
            |
Nuclei targeted validation (optional)
            |
SQLite inventory -> change diff -> Markdown report
```

核心代码按职责拆分，CLI 入口只保留参数解析和任务分发：

| 目录/文件 | 职责 |
| --- | --- |
| [`main.go`](main.go) | CLI 参数、任务创建和顶层编排 |
| [`internal/workflow`](internal/workflow) | 网段工作流、取消检查、进度和漏洞验证调度 |
| [`internal/pipeline`](internal/pipeline) | CIDR 主机发现和域名收集流水线 |
| [`internal/scan`](internal/scan) | 并发端口扫描与内网快速画像 |
| [`internal/identify`](internal/identify) | Banner 读取、基础服务与产品识别 |
| [`internal/domain`](internal/domain) | crt.sh/搜索引擎/字典收集、DNS 策略和泛解析处理 |
| [`internal/planner`](internal/planner) | 服务到 Nuclei 模板 tags 的 v1 定向规划 |
| [`internal/vuln`](internal/vuln) | Nuclei 二进制、模板目录发现和 JSONL 结果解析 |
| [`internal/storage`](internal/storage) | SQLite 初始化、迁移、库存、任务、漏洞和变化持久化 |
| [`internal/api`](internal/api) | HTTP API 与控制台路由挂载 |
| [`internal/web`](internal/web) | 轻 Web 控制台 |
| [`internal/report`](internal/report) | Markdown 报告生成与读取 |

## 快速开始

### 环境要求

- Go `1.26.1+`
- Linux、macOS 或 Windows
- 本地可写目录，用于 `asm.db`、临时文件和 `reports/`
- 漏洞验证额外需要本地安装 `nuclei` 和 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- 搜索引擎动态页面采集建议准备 Playwright 运行环境；不可用时会降级为 Colly HTTP 采集

### 构建

```bash
go build -o yscan .
```

首次运行会在当前工作目录初始化 SQLite 数据库。

### 内网网段巡检

```bash
./yscan subnet 192.168.10.0/24
```

也可以使用 `scan <cidr>`，两者都会走网段快速画像工作流：发现存活主机、扫描内网基线端口、更新库存并生成变化摘要。

```bash
./yscan scan 192.168.10.0/24
./yscan subnet 192.168.10.0/24 --vuln
```

启用 `--vuln` 前，请确认 Nuclei 二进制和模板目录已就绪：

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
./yscan --templates /path/to/nuclei-templates subnet 192.168.10.0/24 --vuln
```

模板目录也可以通过 `NUCLEI_TEMPLATES` 指定。未传入 `--templates` 时，程序会依次探测环境变量、用户目录和当前目录下的常见 templates 路径。

### 单目标扫描与直接验证

```bash
./yscan scan 192.168.1.10
./yscan --templates /path/to/nuclei-templates scan 192.168.1.10 --vuln
./yscan --templates /path/to/nuclei-templates vuln 192.168.1.10:8080
```

`vuln <ip>` 会优先使用数据库中该 IP 的历史开放端口；没有历史结果时默认使用 `80`。

### 域名资产收集

```bash
./yscan --dns-mode internal domain corp.local
./yscan --dns-mode internal domain corp.local --scan
./yscan --templates /path/to/nuclei-templates --dns-mode external \
  domain example.com --scan --vuln
```

DNS 模式用于处理内网、代理/TUN 和外网解析视角的冲突：

| 模式 | 行为 | 典型场景 |
| --- | --- | --- |
| `internal` | 保留私网地址 | 企业办公网、IDC 内网、实验室 |
| `external` | 过滤 RFC1918、Loopback、Link-local 等地址 | 经授权的外部资产核验、TUN/透明代理环境 |
| `hybrid` | 同时保留公网与私网地址 | 解析边界尚不明确的混合网络 |

对于明确的本地代理污染网段，可重复传入 `--dns-deny-cidr`：

```bash
./yscan --dns-mode external --dns-deny-cidr 192.168.18.0/24 \
  domain example.com --scan
```

被动收集结果仍会经过 DNS 活性校验；泛解析过滤只作用于主动字典爆破结果，避免误删被动发现到的资产线索。

## Web 控制台与 API

启动服务：

```bash
./yscan api :8080
```

访问地址：

- 控制台：`http://127.0.0.1:8080/tasks`
- 资产列表：`http://127.0.0.1:8080/assets`
- 漏洞与报告：`http://127.0.0.1:8080/reports`

API 与 CLI 使用同一个 SQLite 数据库。启动 API 时也可以传入全局 Nuclei 与 DNS 参数：

```bash
./yscan --templates /path/to/nuclei-templates --dns-mode internal api :8080
```

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/tasks` | 查询任务列表 |
| `POST` | `/api/tasks` | 创建异步任务 |
| `GET` | `/api/tasks/{id}` | 查询任务详情 |
| `POST` | `/api/tasks/{id}/cancel` | 取消任务 |
| `GET` | `/api/tasks/{id}/changes` | 查询主机和端口变化 |
| `GET` | `/api/tasks/{id}/findings` | 查询漏洞结果 |
| `GET` | `/api/tasks/{id}/report` | 读取 Markdown 报告 |
| `GET` | `/api/assets?active=true` | 查询资产库存 |
| `GET` | `/api/assets/{ip}` | 查询资产及端口详情 |

创建网段任务示例：

```bash
curl -X POST http://127.0.0.1:8080/api/tasks \
  -H 'Content-Type: application/json' \
  -d '{"type":"scan_subnet","target":"192.168.10.0/24"}'
```

支持的任务类型：`scan_ip`、`scan_ip_vuln`、`scan_subnet`、`scan_subnet_vuln`、`vuln_ip`、`collect_domain`、`collect_and_scan`、`collect_scan_vuln`。

## 数据与持续巡检

`yscan` 将状态写入当前目录的 SQLite 数据库，并在任务完成时生成报告：

| 数据 | 位置 | 作用 |
| --- | --- | --- |
| SQLite 数据库 | `asm.db` | 任务、主机库存、端口、漏洞、变化摘要和服务规则 |
| Markdown 报告 | `reports/task-<id>.md` | 任务摘要、资产变化、端口变化和漏洞结果 |

持续巡检的关键不是重复扫描，而是比较两次结果：

- 新资产：新的存活主机进入库存。
- 失活资产：本轮未发现的历史主机标记为非活跃。
- 新开放端口：本轮出现而上轮没有的端口。
- 关闭端口：上轮存在而本轮未发现的端口。

建议以系统定时任务或 CI 调度器按周期运行相同 CIDR，并从控制台或 `reports/` 读取增量结果。

## CLI 参考

| 命令 | 说明 |
| --- | --- |
| `scan <ip\|cidr> [--vuln]` | 扫描单 IP；CIDR 自动进入网段快速画像 |
| `subnet <cidr> [--vuln]` | 显式创建网段巡检任务 |
| `vuln <ip\|ip:port>` | 使用本地 Nuclei 直接验证目标 |
| `domain <domain> [--scan] [--vuln]` | 收集域名资产，可继续端口扫描和漏洞验证 |
| `list` | 列出历史任务 |
| `status <task_id>` | 查看任务状态 |
| `cancel <task_id>` | 取消任务 |
| `findings <task_id> [severity]` | 查看漏洞结果 |
| `api [addr]` | 启动 API 和 Web 控制台 |

全局参数：

| 参数 | 说明 |
| --- | --- |
| `--templates <dir>` | 指定 Nuclei templates 根目录 |
| `--dns-mode internal\|external\|hybrid` | 指定 DNS 解析策略 |
| `--dns-deny-cidr <cidr>` | 添加 DNS 结果排除网段，可重复传入 |

## 安全边界

- 仅对你拥有或已获得明确授权的资产、网段和域名执行扫描。
- Nuclei templates 的内容、影响范围和许可证由操作者负责审查；生产环境应先使用受控模板集验证。
- `yscan` v1 不是漏洞修复、工单、资产归属、RBAC、多租户或互联网全量测绘平台。
- 数据库与报告可能包含内部 IP、服务和漏洞信息；提交 Issue、日志或截图前应完成脱敏。

## v2 路线

v2 不追求无边界堆功能，优先补足“服务识别结果是否可靠、漏洞验证是否足够定向”这条链路：

1. 建立第三方指纹规则的来源、许可证、版本和校验值台账。
2. 引入可复现的本地规则快照编译流程，优先评估 FingerprintHub，并审计 Wappalyzer 数据边界。
3. 增加 Header、Body、Title、Banner 和 favicon 的证据采集与置信度输出。
4. 解析本地 Nuclei 模板元数据，建立安全策略和基于产品/CPE/版本的候选规划。
5. 用高置信度指纹逐步替换 v1 静态服务 tags，同时保留可解释的回退路径。

完整任务拆分、文件边界和验收标准见 [技术设计方案.md](技术设计方案.md)。产品定位与国内 CAASM 产品调研见 [产品调研.md](产品调研.md)。仓库内 AI 开发约束见 [AGENTS.md](AGENTS.md)。

## 开发验证

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o yscan .
```

## 贡献

提交 Issue 或 Pull Request 前，请说明复现步骤、运行环境、脱敏后的输入与预期行为。涉及漏洞、内部资产信息或高影响扫描行为的问题，请勿公开提交真实目标、凭据、扫描结果或可利用数据。
