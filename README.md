# yscan

**轻量化 CAASM（Cyber Asset Attack Surface Management）系统**

`yscan` 是一个以 Go 实现、面向企业内网的资产持续发现与风险验证工具。它以单机部署和 SQLite 状态模型为基础，把网段发现、端口与服务画像、增量变化跟踪、定向漏洞验证和轻 Web 控制台连接为一条可持续运行的闭环。

> 当前版本聚焦经授权的企业内网 IPv4 环境。历史域名任务数据仍可读取，但 V2 不提供域名收集、公网测绘、未授权扫描或重型安全运营平台能力。

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
| 内网资产发现 | IPv4 CIDR 展开、ICMP/TCP 存活探测 | 网段任务有主机数量上限，取消先进入 `cancel_requested`，执行器退出后再进入最终状态 |
| 服务画像 | 单 IP 全端口或显式端口集合、网段基线或显式端口集合、TCP/Web 统一指纹 | 规则命中保留来源修订、规则 ID、版本/CPE、证据摘要与冲突候选 |
| 资产状态管理 | SQLite IP 聚合库存与范围主机/端口成员关系 | 记录全局和范围级 `first_seen`、`last_seen`、`is_active`，重叠 CIDR 的主机和端口变化互不覆盖 |
| 漏洞验证 | 本地 [Nuclei](https://github.com/projectdiscovery/nuclei) 调用与 JSONL 解析 | 使用本地 templates，服务标签只缩小候选范围，默认排除 `intrusive`、`dos`、`auth` |
| 报告 | Markdown 运行报告 | 每轮 `ScanTaskRun` 终态后生成 `reports/scan-task-<taskId>-run-<runId>.md` |
| 接口与控制台 | HTTP API + 轻 Web 控制台 | 支持逻辑任务、运行历史、变化、漏洞与运行级报告查看 |

## 架构

```text
CLI / HTTP API / Web Console
            |
       Task Orchestrator
            |
  +---------+----------+
  |                    |
Single target      Subnet workflow
  |                    |
Full/selected ports Host discovery
  |                    |
Protocol profile   Baseline/selected ports
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
| [`internal/planner`](internal/planner) | 服务到 Nuclei 模板 tags 的定向候选规划 |
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
./yscan subnet 192.168.10.0/24 --port-spec 22,80,443,8000-8100
```

`scan` 和 `subnet` 都创建 V2 一次性 `ScanTaskRun`，因此 CLI、API 和 Web 会看到同一份任务、资产快照、Diff 与报告。目标仅允许 RFC1918 或本机 Loopback IPv4；公网、Link-local、组播和跨越内外网边界的 CIDR 会在创建任务前被拒绝。

启用 `--vuln` 前，请确认 Nuclei 二进制和模板目录已就绪：

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
./yscan --templates /path/to/nuclei-templates subnet 192.168.10.0/24 --vuln
```

模板目录也可以通过 `NUCLEI_TEMPLATES` 指定。未传入 `--templates` 时，程序会依次探测环境变量、用户目录和当前目录下的常见 templates 路径。

所有 Nuclei 调用默认传入 `-exclude-tags intrusive,dos,auth`。服务标签只用于缩小模板候选范围，不代表模板一定无副作用；生产环境仍应审查实际模板内容并先在受控资产上验证。

### 单目标扫描与漏洞验证

```bash
./yscan scan 192.168.1.10
./yscan --templates /path/to/nuclei-templates scan 192.168.1.10 --vuln
./yscan scan 192.168.1.10 --port-spec 22,80,443,8080
```

旧 V1 的直接 `vuln` 与 `domain` 任务创建入口已关闭。漏洞验证通过 V2 `scan --vuln` 或 ScanTask 配置启用；旧数据只能用 `legacy-list`、`legacy-status` 和 `legacy-findings` 读取。

### DNS 解析策略

DNS 模式用于处理 V2 工作流中的内网解析视角：

| 模式 | 行为 | 典型场景 |
| --- | --- | --- |
| `internal` | 保留私网地址 | 企业办公网、IDC 内网、实验室 |
| `external` | 过滤 RFC1918、Loopback、Link-local 等地址 | 兼容历史配置，不扩大扫描目标准入范围 |
| `hybrid` | 同时解析不同视角 | 兼容历史配置，最终扫描目标仍须通过内网校验 |

对于明确的本地代理污染网段，可重复传入 `--dns-deny-cidr`：

```bash
./yscan --dns-mode internal --dns-deny-cidr 192.168.18.0/24 \
  subnet 192.168.10.0/24
```

被动收集结果仍会经过 DNS 活性校验；泛解析过滤只作用于主动字典爆破结果，避免误删被动发现到的资产线索。

## Web 控制台与 API

启动服务：

```bash
./yscan api 127.0.0.1:8080
```

访问地址：

- 控制台：`http://127.0.0.1:8080/tasks`
- 资产列表：`http://127.0.0.1:8080/assets`
- 漏洞与报告：`http://127.0.0.1:8080/reports`
- 健康检查：`http://127.0.0.1:8080/api/healthz`

API 与 CLI 使用同一个 SQLite 数据库。启动 API 时也可以传入全局 Nuclei 与 DNS 参数：

```bash
./yscan --templates /path/to/nuclei-templates --dns-mode internal api 127.0.0.1:8080
```

回环监听无需访问名单。空 host、`0.0.0.0`、`[::]` 或其他非回环地址会暴露内部资产与指纹数据，因此必须至少配置一个受信客户端 CIDR：

```bash
./yscan api 0.0.0.0:8080 --allow-cidr 192.168.10.0/24
./yscan api '[::]:8080' --allow-cidr 2001:db8:1234::/48
```

可重复使用 `--allow-cidr`。监听校验和每个请求的 `RemoteAddr` 授权都会执行；不在名单内的客户端返回 `403`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/scan-tasks` | 查询 v2 逻辑任务列表 |
| `POST` | `/api/scan-tasks` | 创建一次性或定期逻辑任务 |
| `GET` | `/api/scan-tasks/{taskId}` | 查询逻辑任务配置与状态 |
| `PUT` | `/api/scan-tasks/{taskId}` | 更新后续运行的目标、计划和配置；已有运行保持原配置快照 |
| `GET` | `/api/scan-tasks/{taskId}/runs` | 查询该逻辑任务的运行历史 |
| `POST` | `/api/scan-tasks/{taskId}/run-now` | 立即触发一个启用中的定期任务 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}` | 查询不可变运行快照元数据、状态与 `report_error` |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/changes` | 查询本轮与同任务成功基线的变化 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/report` | 读取该运行的 Markdown 报告 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/audit-report` | 读取该运行的审计报告 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/findings` | 分页读取结构化漏洞结果与验证状态 |
| `POST` | `/api/scan-tasks/{taskId}/runs/{runId}/cancel` | 请求取消当前运行；终态运行不可取消 |
| `POST` | `/api/scan-tasks/{taskId}/pause` | 暂停逻辑任务，暂停后不再创建新运行 |
| `POST` | `/api/scan-tasks/{taskId}/resume` | 恢复已暂停的任务 |
| `POST` | `/api/scan-tasks/{taskId}/archive` | 归档逻辑任务，归档后不可恢复 |
| `GET` | `/api/assets?active=true&scope=subnet:192.168.10.0/24` | 查询 IP 聚合库存，可按扫描范围精确过滤 |
| `GET` | `/api/assets/{ip}` | 查询资产聚合状态、全部范围成员及端口详情 |
| `GET` | `/api/healthz` | 检查 API 与 SQLite 是否可用 |
| `GET` | `/api/fingerprints/sources` | 查询规则来源与 active 修订摘要 |
| `GET` | `/api/fingerprints/imports?page=1&page_size=50` | 分页查询 import 摘要，不返回大型 manifest |
| `GET` | `/api/fingerprints/imports/{importId}` | 按需查询单个 import 及 manifest |
| `GET` | `/api/fingerprints/sources/{sourceKey}/rules` | 按规则 ID、产品、状态分页检索原始规则 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/fingerprints/{imports\|matches\|conclusions}` | 分页查询本轮冻结修订、命中和结论 |

创建每天执行的网段逻辑任务示例：

```bash
curl -X POST http://127.0.0.1:8080/api/scan-tasks \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.10.0/24","scan_type":"subnet","mode":"scheduled","cron":"0 2 * * *","timezone":"Asia/Shanghai"}'
```

`POST` 与 `PUT /api/scan-tasks` 使用同一请求模型：`scan_type` 只能是 `ip` 或 `subnet`；`mode` 为 `once` 或 `scheduled`；`scheduled` 模式必须提供 5 段 `cron` 和 IANA `timezone`；`config.port_spec` 可指定端口集合；通过 `config.vulnerability_on: true` 启用定向漏洞验证。旧 `/api/tasks` 只读，创建和取消会返回 `410 Gone`。

### 任务取消与报告

取消不是立即伪装成已停止：运行中或排队中的任务先变为 `cancel_requested`，端口扫描、网段工作流和 Nuclei 子进程会收到同一取消上下文；执行器实际退出后，任务才进入 `canceled`。取消前已经保存的结果会保留，但不会被视为成功运行。

每轮 ScanTaskRun 完成时先持久化最终状态、完成时间及已收集结果，再生成 Markdown 报告。成功、失败和取消运行都会尝试生成报告；若报告写入失败，运行状态不会被改写，错误会记录在该运行的 `report_error` 字段中，并可通过运行详情 API 查询。

## 数据与持续巡检

`yscan` 将状态写入当前目录的 SQLite 数据库，并在任务进入最终状态后生成报告：

| 数据 | 位置 | 作用 |
| --- | --- | --- |
| SQLite 数据库 | `asm.db` | 逻辑任务、运行快照、IP 聚合库存、范围主机/端口成员、漏洞、变化摘要和服务规则 |
| Markdown 报告 | `reports/scan-task-<taskId>-run-<runId>.md` | 每轮成功、失败或取消运行的最终摘要、任务内变化、端口变化和漏洞结果 |

持续巡检的关键不是重复扫描，而是在同一扫描范围内比较两次结果：

- 新资产：新的存活主机进入库存。
- 失活资产：本轮未发现的历史主机标记为非活跃。
- 新开放端口：本轮出现而上轮没有的端口。
- 关闭端口：上轮存在而本轮未发现的端口。

范围主机与端口成员关系独立于 IP 聚合库存。一个 IP 同时属于 `/16` 和其中 `/24` 时，两次巡检不会覆盖对方的主机、端口成员状态或变化摘要；全局 IP 状态只要存在一个活跃范围成员就保持活跃，`first_seen` 取最早发现时间，`last_seen` 取所有成员最新的成功发现时间。资产 API 返回 `scope_count`，详情返回每个范围成员；旧 `source` 查询参数仅保留一版兼容别名，不能再用作资产唯一归属。

使用 `yscan schedule create --mode scheduled` 为 CIDR 创建内置定期任务。API 服务进程负责按 Cron 与任务时区创建运行记录、保留运行快照并计算同任务 Diff；控制台“漏洞与报告”页可选择逻辑任务与具体运行查看报告。外部 Cron 或 CI 不应重复触发同一巡检任务。

## CLI 参考

| 命令 | 说明 |
| --- | --- |
| `scan <ip\|cidr> [--vuln] [--port-spec <ports>]` | 创建并同步执行 V2 一次性任务；CIDR 自动使用网段工作流 |
| `subnet <cidr> [--vuln] [--port-spec <ports>]` | 创建并同步执行 V2 网段一次性任务 |
| `list` | 列出 V2 逻辑任务 |
| `status <scan_task_id>` | 查看 V2 逻辑任务配置 |
| `cancel <scan_task_id> <run_id>` | 取消 V2 排队中或运行中的一轮 |
| `findings <scan_task_id> <run_id>` | 查看 V2 结构化漏洞结果 |
| `changes <scan_task_id> <run_id> [baseline_run_id]` | 查看同一逻辑任务内的 Diff |
| `report <scan_task_id> <run_id> [--audit]` | 读取用户报告或审计报告 |
| `asset <internal_ip>` | 读取资产端点画像 |
| `schedule create --target <ip-or-cidr> --scan-type ip\|subnet --mode once\|scheduled ...` | 创建 v2 逻辑任务；scheduled 模式由 API 服务内置调度 |
| `schedule update <scan_task_id> ...` | 更新逻辑任务后续运行的目标、计划与配置；已有运行保留原快照 |
| `schedule list` | 列出全部 v2 逻辑任务 |
| `schedule show <scan_task_id>` | 查看逻辑任务的配置、状态和计划 |
| `schedule runs <scan_task_id>` | 查看任务的运行历史和报告路径 |
| `schedule run <scan_task_id>` | 立即触发一个启用中的定期任务 |
| `schedule run-show <scan_task_id> <run_id>` | 查看运行状态、阶段、进度与报告诊断 |
| `schedule changes\|findings\|report <scan_task_id> <run_id>` | 查看运行 Diff、漏洞和报告 |
| `schedule pause\|resume\|archive <scan_task_id>` | 暂停、恢复或归档逻辑任务 |
| `legacy-list\|legacy-status\|legacy-findings` | 只读访问 V1 历史记录；不能再创建或取消 V1 任务 |
| `fingerprint list` | 列出规则来源和当前 active import |
| `fingerprint import --source <source_key> [--recovery-archive <path>]` | 校验并导入一个固定来源或显式恢复归档 |
| `fingerprint upgrade [--source <source_key>]` | 显式升级全部或单个嵌入来源；逐来源输出成功/失败诊断 |
| `fingerprint cleanup [--apply]` | 列出无引用的非活动修订；默认 dry-run，只有 `--apply` 才事务删除 |
| `fingerprint mapping list` | 列出本地审核的规则到 Nuclei 模板映射 |
| `fingerprint mapping import --manifest <path> --templates <root>` | 校验模板 SHA 后导入审核映射修订 |
| `fingerprint mapping disable --id <id>` | 停用一条模板映射 |
| `api [addr] [--allow-cidr <cidr>]...` | 启动 API 和 Web 控制台；非回环监听必须配置受信 CIDR |

## 安装与服务运行

本机构建、测试、安装或生成当前平台发布产物：

```bash
make build
make test
sudo make install
make release
```

systemd 示例位于 [`deploy/yscan.service`](deploy/yscan.service)。下面的命令创建专用用户和可写状态目录，安装后默认只监听回环地址：

```bash
sudo useradd --system --home /var/lib/caasm --shell /usr/sbin/nologin caasm
sudo install -d -o caasm -g caasm -m 0750 /var/lib/caasm /etc/caasm
sudo install -m 0644 deploy/yscan.service /etc/systemd/system/yscan.service
sudo systemctl daemon-reload
sudo systemctl enable --now yscan
curl --fail http://127.0.0.1:8080/api/healthz
```

`SIGINT` 和 `SIGTERM` 会停止接收新请求、取消当前进程启动的扫描并在最多 10 秒内关闭 HTTP 服务。启动恢复会将上次进程遗留的运行转为明确终态，并生成失败或取消报告。

全局参数：

| 参数 | 说明 |
| --- | --- |
| `--templates <dir>` | 指定 Nuclei templates 根目录 |
| `--dns-mode internal\|external\|hybrid` | 指定 DNS 解析策略 |
| `--dns-deny-cidr <cidr>` | 添加 DNS 结果排除网段，可重复传入 |

## 安全边界

- 仅对你拥有或已获得明确授权的资产、网段和域名执行扫描。
- Nuclei templates 的内容、影响范围和许可证由操作者负责审查；生产环境应先使用受控模板集验证。
- `yscan` 不是漏洞修复、工单、资产归属、RBAC、多租户或互联网全量测绘平台。
- 数据库与报告可能包含内部 IP、服务和漏洞信息；提交 Issue、日志或截图前应完成脱敏。
- API 没有应用层登录机制；非回环部署必须结合 `--allow-cidr`、主机防火墙和受控管理网络，不能直接暴露到互联网。

## v2 路线

v2 不追求无边界堆功能，优先补足“服务识别结果是否可靠、漏洞验证是否足够定向”这条链路。此前两条样例规则、文件快照和硬编码置信度组成的指纹原型已经撤回，不能视为指纹库能力。

M11 随单二进制嵌入 9 个固定第三方来源，共归档 41,192 条原始规则；当前 28,512 条进入统一可执行投影，12,680 条以明确原因保留为 `unsupported`。另有本地旧 `banner` 规则迁移投影。空数据库首次启动会逐来源初始化嵌入规则；首次初始化中失败或缺失的来源会保留诊断并在下次启动单独重试，已有任意历史 import 的来源不会被自动升级。规则升级仍必须显式执行 `fingerprint upgrade`。

可执行范围包括 FingerprintHub Web/Service 的被动条件、WhatWeb 可静态提取条件、Wappalyzer 被动 HTTP 条件、Nmap NULL Probe，以及固定只读白名单中的 TCP payload Probe。仍不执行动态 Ruby、DOM/JavaScript 行为、无法保真投影的隐式关系、UDP Probe、认证/写入/状态变更探针和未审核的 Nuclei 模板。互联网 CVE/POC 自动同步属于后续边界，不在当前版本中。

资产详情和用户报告以同一个观测运行展示端口、协议证据、基础服务、角色化技术栈、版本/CPE、识别来源和漏洞验证摘要。启用漏洞验证时，人工审核映射优先；其余已识别产品会从显式指定的本地 Nuclei 模板目录建立内容固定索引，只选择规范产品名、CPE 或精确产品标签匹配且通过低副作用策略的模板。没有产品、没有映射、模板被策略过滤和执行失败均会单独说明，不会显示成“验证成功且无漏洞”。Nuclei 可执行文件和模板目录不嵌入 CAASM 二进制，仍须由部署环境提供。

## 开发验证

```bash
go test ./...
go test -race ./...
go vet ./...
go build -o yscan .
./scripts/verify-t293.sh
# 需要 Docker Compose v2、Nuclei，并占用本机 22/80/443/3306/6379/8080
./scripts/verify-t293-products.sh
# 需要预先启动脚本所列的真实 Redis、Dropbear、PHP 和 Flask 本地服务
./scripts/verify-t330.sh
```

## 贡献

提交 Issue 或 Pull Request 前，请说明复现步骤、运行环境、脱敏后的输入与预期行为。涉及漏洞、内部资产信息或高影响扫描行为的问题，请勿公开提交真实目标、凭据、扫描结果或可利用数据。
