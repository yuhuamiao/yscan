# yscan

`yscan` 是一个面向企业内网的 CAASM（Cyber Asset Attack Surface Management）工具，用于发现资产、识别服务并验证风险。

给它一个内网 IP 或 CIDR，它会发现存活主机和开放端口，识别服务及 Web 技术栈，并把每次扫描保存到本地 SQLite 数据库。后续扫描可以直接看到新增资产、端口变化和漏洞变化。日常操作既可以使用命令行，也可以在浏览器控制台完成。

`yscan` 适合单机或小型服务器部署，不需要 Elasticsearch、Redis、消息队列或 Kubernetes。漏洞验证依赖本机安装的 Nuclei；如果没有 Nuclei，资产发现和服务识别仍可正常使用。

## 主要功能

- 扫描单个内网 IP 或内网网段
- 扫描全部 TCP 端口，或使用明确的端口范围
- 识别 TCP 服务、HTTP/HTTPS、Web Server、运行时、框架、应用和前端组件
- 保存版本、CPE、规则来源和安全的证据摘要
- 按任务比较两次成功扫描的主机、端口和漏洞变化
- 根据识别结果选择经过安全检查的本地 Nuclei 模板
- 支持一次性任务、Cron 定时任务、进度查看和取消
- 提供命令行、HTTP API、Web 控制台及 Markdown 报告

## 使用范围

`yscan` 只接受 RFC1918 私网地址和本机 Loopback IPv4。公网地址、Link-local、组播地址、未指定地址以及跨越内外网边界的 CIDR 会被拒绝。

请只扫描你拥有或已经获得明确授权的目标。

## 环境要求

- Go `1.26.1` 或更高版本
- Linux 或 WSL；Windows 是后续正式发布方向，当前尚未完成原生验收
- WSL 的 `/mnt/c`、`/mnt/d` 可以使用；升级和搬迁前仍建议先停止进程并备份目录
- 漏洞验证需要本机安装 `nuclei` 和 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

## 构建

```bash
make build
```

也可以直接使用 Go：

```bash
go build -o yscan .
```

查看帮助不会创建数据库：

```bash
./yscan --help
```

首次执行扫描、启动服务或管理指纹库时，程序会在二进制所在目录创建 `.env`、`data/`、`reports/`、`logs/` 和 `run/`。从其他工作目录调用同一个二进制，仍使用这套数据。

从旧版升级时先停止所有 `yscan` 进程，再显式迁移旧目录。旧便携部署把原来存放 `asm.db` 的目录传给 `--from-home`：

```bash
/opt/yscan/yscan --home /opt/yscan upgrade --from-home /path/to/old-yscan
```

旧 systemd 部署的数据通常位于 `/var/lib/yscan`：

```bash
sudo /opt/yscan/yscan --home /opt/yscan upgrade --from-home /var/lib/yscan
```

迁移会通过 SQLite 一致快照恢复可能存在的热 journal，并复制旧报告。若新 home 为空但当前工作目录发现旧 `asm.db`，程序会拒绝创建空库并打印对应迁移命令。

## 快速开始

扫描单个 IP：

```bash
./yscan scan 192.168.1.10
```

扫描网段：

```bash
./yscan subnet 192.168.10.0/24
```

指定端口：

```bash
./yscan scan 192.168.1.10 --port-spec 22,80,443,8000-8100
./yscan subnet 192.168.10.0/24 --port-spec 22,80,443
```

端口表达式支持单个端口、逗号分隔和闭区间。单 IP 未指定端口时扫描全部 TCP 端口；网段未指定端口时使用内置的常见端口集合。

每次命令行扫描都会创建任务和运行记录，扫描结束后可以在 CLI、API 和 Web 中查看同一份资产、漏洞和报告数据。

## 漏洞验证

先安装 Nuclei：

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

使用 systemd 时，服务以 `yscan` 用户运行，不能依赖管理员个人目录下的 `~/go/bin`。应将二进制安装到系统路径，或在 `/opt/yscan/.env` 中配置运行用户可访问的绝对路径：

```bash
sudo install -m 0755 "$(go env GOPATH)/bin/nuclei" /usr/local/bin/nuclei
sudo -u yscan /usr/local/bin/nuclei -version

# 也可以显式配置自带工具和模板目录
YSCAN_NUCLEI_BINARY=/opt/yscan/tools/nuclei
YSCAN_NUCLEI_TEMPLATES=/opt/yscan/nuclei-templates
```

绝对路径方案需确保 `yscan` 用户对 Nuclei 有执行权限、对模板目录有读取权限；启服前应以 `yscan` 用户执行一次版本和模板读取检查。

指定模板目录并启用验证：

```bash
./yscan --templates /path/to/nuclei-templates scan 192.168.1.10 --vuln
./yscan --templates /path/to/nuclei-templates subnet 192.168.10.0/24 --vuln
```

模板目录也可以通过 `YSCAN_NUCLEI_TEMPLATES` 环境变量或同目录 `.env` 指定。旧的 `NUCLEI_TEMPLATES` 仅作为启动时兼容输入：Server 会立即将它解析成固定路径并冻结到任务配置，扫描执行阶段不会再次读取该变量。未配置模板目录时，漏洞验证会明确报告模板目录缺失，不会从当前工作目录或用户目录隐式选择模板。

`yscan` 不会对每个端口执行整套模板。它会先根据服务、产品和 CPE 选择候选模板，再应用只读策略和审核清单。Nuclei 进程默认禁用交互和重定向，限制为每秒 25 个请求、5 个并发，并排除 `intrusive`、`dos`、`auth` 标签。

页面会明确区分以下结果：

- 未启用漏洞验证
- 没有识别出可映射产品
- 没有可用模板
- 模板被安全策略过滤
- 已执行且没有发现漏洞
- 已发现漏洞
- Nuclei 或模板执行失败

Nuclei 可执行文件和模板不会打包进 `yscan`，需要由部署环境单独维护。

资产识别使用的内置指纹规则随 `yscan` 单二进制发布，首次业务运行会把固定修订初始化到本地数据库；规则升级只由显式的 `fingerprint upgrade` 命令触发。

## Web 控制台

前台启动服务：

```bash
./yscan server
```

监听地址、受信 CIDR、SQLite 等待时间和 Nuclei 路径可以写入同目录 `.env`。配置优先级为命令行参数、进程环境变量、`.env`、内置默认值；修改后重启服务生效。

当前调度执行的有效并发固定为 `1`。`.env` 中 `YSCAN_MAX_CONCURRENCY` 会作为后续并发能力的期望配置保存并显示，但在并发调度正式启用前不会提高实际并发，避免产生重叠扫描和旧观测覆盖。

常用页面：

- 任务：`http://127.0.0.1:8080/tasks`
- 一次性扫描：`http://127.0.0.1:8080/executions`
- 资产：`http://127.0.0.1:8080/assets`
- 漏洞与报告：`http://127.0.0.1:8080/reports`
- 指纹管理：`http://127.0.0.1:8080/fingerprints`
- 健康检查：`http://127.0.0.1:8080/api/healthz`

控制台可以创建一次性扫描和定时任务，设置端口范围、漏洞验证、每日或每周计划，并查看运行阶段、进度、Diff 和报告。活动运行的详情每 3 秒更新一次，可以直接取消。

### 允许其他主机访问

API 没有登录页面。监听非回环地址时，必须至少配置一个允许访问的客户端 CIDR：

```bash
./yscan server 0.0.0.0:8080 --allow-cidr 192.168.10.0/24
```

`--allow-cidr` 可以重复使用。不在允许范围内的客户端会收到 `403`。不要把 API 直接暴露到互联网。

## 定时扫描

Server 进程同时负责 Web、API 和定时任务调度。创建一个每天凌晨 2 点执行的网段任务：

```bash
./yscan schedule create \
  --target 192.168.10.0/24 \
  --scan-type subnet \
  --mode scheduled \
  --cron '0 2 * * *' \
  --timezone Asia/Shanghai \
  --port-spec 22,80,443
```

立即执行已有的定时任务：

```bash
./yscan schedule run <task_id>
```

暂停或恢复任务：

```bash
./yscan schedule pause <task_id>
./yscan schedule resume <task_id>
```

请不要再用外部 Cron 重复触发同一个定时任务。若调度器发生不可恢复的错误，API 服务会同时退出；配合仓库中的 systemd unit，服务会由 systemd 重新启动。

## CLI 参考

常用命令：

| 命令 | 说明 |
| --- | --- |
| `scan <ip\|cidr> [--vuln] [--port-spec <ports>]` | 执行一次扫描并等待完成 |
| `subnet <cidr> [--vuln] [--port-spec <ports>]` | 执行一次网段扫描并等待完成 |
| `list` | 列出任务 |
| `status <task_id>` | 查看任务配置 |
| `cancel <task_id> <run_id>` | 取消排队中或运行中的一轮扫描 |
| `findings <task_id> <run_id>` | 查看漏洞结果 |
| `changes <task_id> <run_id> [baseline_run_id]` | 查看主机、端口和漏洞变化 |
| `report <task_id> <run_id> [--audit]` | 查看用户报告或审计报告 |
| `asset <internal_ip>` | 查看资产及端点画像 |
| `server [addr] [--allow-cidr <cidr>]...` | 前台启动 Server、API 和 Web 控制台 |

任务管理命令：

| 命令 | 说明 |
| --- | --- |
| `schedule create ...` | 创建一次性或定时任务 |
| `schedule update <task_id> ...` | 修改任务后续运行使用的配置 |
| `schedule list` | 列出任务 |
| `schedule show <task_id>` | 查看任务配置和状态 |
| `schedule runs <task_id>` | 查看运行历史 |
| `schedule run <task_id>` | 立即执行定时任务 |
| `schedule run-show <task_id> <run_id>` | 查看运行阶段、进度和错误 |
| `schedule cancel <task_id> <run_id>` | 取消一轮扫描 |
| `schedule changes <task_id> <run_id> [baseline_run_id]` | 查看变化 |
| `schedule findings <task_id> <run_id>` | 查看漏洞结果 |
| `schedule report <task_id> <run_id> [--audit]` | 查看报告 |
| `schedule pause\|resume\|archive <task_id>` | 暂停、恢复或归档任务 |

指纹管理命令：

| 命令 | 说明 |
| --- | --- |
| `fingerprint list` | 查看指纹来源和当前规则修订 |
| `fingerprint upgrade [--source <source_key>]` | 升级全部或指定的内置规则来源 |
| `fingerprint cleanup [--apply]` | 查看或删除没有引用的旧规则修订 |
| `fingerprint mapping list` | 查看人工维护的模板映射 |
| `fingerprint mapping import --manifest <path> --templates <root>` | 校验模板哈希并导入映射 |
| `fingerprint mapping disable --id <id>` | 停用模板映射 |

`legacy-list`、`legacy-status` 和 `legacy-findings` 只用于读取旧格式任务数据，不会创建新的扫描任务。

## HTTP API

下面是日常使用最常见的接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/healthz` | 健康检查 |
| `GET` / `POST` | `/api/scan-tasks` | 查询或创建任务 |
| `GET` / `PUT` | `/api/scan-tasks/{taskId}` | 查询或修改任务 |
| `POST` | `/api/scan-tasks/{taskId}/run-now` | 立即执行定时任务 |
| `GET` | `/api/scan-tasks/{taskId}/runs` | 查询运行历史 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}` | 查询运行状态和进度 |
| `POST` | `/api/scan-tasks/{taskId}/runs/{runId}/cancel` | 取消运行 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/changes` | 查询变化 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/findings` | 查询漏洞结果 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/report` | 读取用户报告 |
| `GET` | `/api/scan-tasks/{taskId}/runs/{runId}/audit-report` | 读取审计报告 |
| `GET` | `/api/assets?active=true` | 查询资产 |
| `GET` | `/api/assets/{ip}` | 查询资产端点详情 |

创建每天执行的任务：

```bash
curl -X POST http://127.0.0.1:8080/api/scan-tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "192.168.10.0/24",
    "scan_type": "subnet",
    "mode": "scheduled",
    "cron": "0 2 * * *",
    "timezone": "Asia/Shanghai",
    "config": {
      "port_spec": "22,80,443",
      "vulnerability_on": false
    }
  }'
```

## 数据与报告

`yscan` 默认把数据写到二进制所在目录：

| 路径 | 内容 |
| --- | --- |
| `.env` | 启动配置 |
| `data/asm.db` | 任务、运行、资产、端口、指纹和漏洞数据 |
| `reports/scan-task-<taskId>-run-<runId>.md` | 给使用者阅读的扫描报告 |
| `reports/scan-task-<taskId>-run-<runId>-audit.md` | 规则修订、证据和模板选择记录 |
| `logs/` | 服务和运行日志 |
| `run/` | Server 进程与健康状态 |

用户报告先展示端点、技术栈、漏洞验证状态和发现结果。规则 ID、哈希、匹配条件等排查信息放在审计报告中。

失败或取消的运行也会保留已经收集的结果并尝试生成报告，但不会成为下一次 Diff 的成功基准。

任务、运行、快照、漏洞和报告默认永久保留。服务完成新运行时不会自动清理超过 90 天的历史；需要控制磁盘占用时，应先备份并等待后续显式清理命令，不要直接删除数据库关联的报告文件。

## 安装为系统服务

安装到单目录 `/opt/yscan` 并安装 systemd unit：

```bash
sudo useradd --system --home /opt/yscan --shell /usr/sbin/nologin yscan
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now yscan
curl --fail http://127.0.0.1:8080/api/healthz
```

systemd 服务和日常 CLI 操作必须使用同一个 `yscan` 用户，避免 SQLite 和报告目录出现混合属主。安装后的二进制为只读；只有 `.env`、`data/`、`reports/`、`logs/` 和 `run/` 归运行用户写入。不建设共享用户组并发访问模型。

服务默认监听 `127.0.0.1:8080`，配置位于 `/opt/yscan/.env`。便携模式停掉所有进程后可整体移动或删除目录；systemd 模式还必须先移除 unit：

```bash
sudo make uninstall
# 确认已备份后，再手工删除 /opt/yscan
```

`yscan server uninstall` 和 `make uninstall` 都只移除 systemd unit，不递归删除 home。数据目录必须由管理员确认备份和路径后手工处理。

旧的 `yscan api` 在一个兼容周期内仍可启动同一 Server，但会输出弃用提示。

收到 `SIGINT` 或 `SIGTERM` 后，服务会停止接收新请求，取消本进程启动的扫描，等待运行退出后关闭。重新启动时会先处理上次未完成的运行并生成报告，然后才开始监听 API。

同一个 home 同时运行多个 Server（包括使用不同监听端口）属于不支持操作。日常使用请通过 `server status`、`start`、`stop` 和 `restart` 管理唯一实例。

生成发布文件：

```bash
make release
```

输出位于 `dist/`，`dist/SHA256SUMS` 保存校验值。

## 安全说明

- 只扫描经过授权的内网资产。
- 数据库和报告可能包含内部 IP、服务版本和漏洞信息，应限制文件访问权限并定期备份。
- 非回环 API 监听必须使用 `--allow-cidr`，并同时配置主机防火墙或受控管理网络。
- 启用漏洞验证前，应审查本地 Nuclei 模板及其许可证，并先在测试环境确认影响。
- `yscan` 不提供漏洞修复、工单、RBAC、多租户或互联网资产测绘功能。

## 开发与测试

```bash
make test
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build ./...
```

## 反馈与贡献

提交 Issue 或 Pull Request 时，请提供复现步骤、运行环境、脱敏后的输入和预期结果。不要公开提交真实内网地址、凭据、扫描报告或漏洞利用数据。
