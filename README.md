# LLM Honeynet 平台指南

LLM Honeynet 是一套围绕影子蜜网构建的攻防研究平台。它整合多协议高仿真蜜罐、阶段化入侵感知、轻量记忆，以及基于大模型的 Honey Agent 与 Trap Agent，用于自动化生成端口诱饵、文件陷阱、跨主机凭证链和脆弱性叙事，从而持续牵制和延迟攻击者。

---

## 核心能力一览
- **多协议蜜罐**：SSH/Telnet/FTP/HTTP/HTTPS/MySQL 等，支持虚拟文件系统与命令诱饵。
- **批量部署**：快捷生成多主机运行目录、证书与独立日志。
- **入侵阶段识别**：基于规则评估 Stage1–Stage5，可选调用 OpenAI 摘要。
- **轻量记忆**：短期树（主机→端口→文件→漏洞类别）+ 长期端口事实，压缩提示上下文。
- **Honey Agent**：生成端口/文件/漏洞类别诱饵，支持微调模式。
- **Trap Agent**：生成主机内文件闭环和跨主机循环链。
- **影子拓扑**：从企业拓扑生成 Mininet 可用的影子网络。

---

## 系统架构
1. **数据输入层**：`enterprise/`（拓扑、文档）、`config/`（协议配置、虚拟文件系统）、`deployments/`（部署副本）。
2. **采集运行层**：`run_honeypot.py` 多协议蜜罐；`shadow/mininet_shadow.py` 影子网络模拟。
3. **分析生成层**：`run_perception.py` 阶段识别；`run_honey_agent.py` / `run_trap_agent.py` 生成诱饵与陷阱。
4. **记忆与检索层**：`shadow/honey_agent.json`、`shadow/trap_agent.json`、`shadow/long_memory.json`、`shadow/attacker_preferences.json`。

---

## 目录结构
| 路径 | 说明 |
| --- | --- |
| `honeypot/` | 多协议服务实现、虚拟文件系统与运行调度 |
| `config/` | 默认协议配置、虚拟文件系统、规则模板 |
| `deployments/` | 多主机部署产物（脚本生成） |
| `enterprise/` | 原始企业拓扑/文档输入 |
| `shadow/` | 影子拓扑与 Agent 输出：`honey_agent.json`、`trap_agent.json`、`long_memory.json`、`attacker_preferences.json` |
| `orchestrator/` | 轻量记忆、Honey Agent、Trap Agent、拓扑工具 |
| `deception/` | 诱饵一致性检测与配置生成 |
| `perception/` | 入侵阶段识别与摘要 |
| `scripts/` | 管道脚本（拓扑转换、部署、实用工具） |
| `logs/` | 本地蜜罐服务日志（NDJSON） |
| `www/` / `ftp/` | HTTP/FTP 静态诱饵内容 |

---

## 关键组件
### 1. 多协议蜜罐 (`run_honeypot.py`)
- 自动读取 `config/` 下 `*_config.json` 启动对应协议。
- 支持 `--services ssh,telnet` 指定子集；日志写入 `logs/<service>.log`。
- 虚拟文件系统定义在 `config/filesystem.json`，SSH/Telnet/FTP 共享。
- 批量部署：`python3 scripts/manage_hosts.py add h1` 或 `bulk/from-topology`。

### 2. 感知管线 (`run_perception.py`)
- 自动发现 `logs/` 与 `deployments/*/logs`，加载规则（Stage1–Stage5）。
- 支持 `--hosts`、`--rules`、`--include-base`；`--openai` 可做摘要。

### 3. 轻量记忆
- 短期记忆树（主机→端口→文件→漏洞类别），长期记忆 `shadow/long_memory.json` 提供端口/服务事实，偏好列表 `shadow/attacker_preferences.json`。

### 4. Honey Agent (`run_honey_agent.py`)
- 三段流水：1) 端口；2) 文件（仅 path，诱饵命名）；3) 漏洞类别（type，引用端口/文件）。
- 模式：`initialization` / `finetune`（读取并微调现有 `honey_agent.json`）。
- 输出：`shadow/honey_agent.json`（可用 `--short-memory` 覆盖）。

### 5. Trap Agent (`run_trap_agent.py`)
- 依赖 Honey Agent 树构造陷阱：
  1. 每机 0–3 条闭环文件链（路径序列）。
  2. 1–3 条跨主机链，steps 形如 host(low)→host(mid)→host(high)→host(low)，steps ≤5。
- 输出：`shadow/trap_agent.json`（包含 host_loops 与 chains）。

### 6. Deception Agent (`run_deception.py`)
- 汇总 `honey_agent.json` + `trap_agent.json`，执行一致性审计、按部署生成配置。
- 支持 `--mode consistency` / `generate-configs` / `full`，可用 `--hosts` 限定目标。
- 审计输出 `shadow/deception_consistency_report.json`，配置写入各 `deployments/<host>/config/`。

### 7. 影子拓扑 (`scripts/build_shadow.py` / `shadow/mininet_shadow.py`)
- `build_shadow.py` 从 `enterprise/enterprise_topology.json` 生成 `shadow/shadow_topology.json` 与 Mininet 脚本。
- `sudo python3 shadow/mininet_shadow.py` 可在 Mininet 中调试影子网络。

---

## 常用命令
| 操作 | 命令 |
| --- | --- |
| 启动蜜罐服务 | `python3 run_honeypot.py [--services ssh,http]` |
| 批量生成部署 | `python3 scripts/manage_hosts.py bulk --prefix h --count 5` |
| 从拓扑生成部署 | `python3 scripts/manage_hosts.py from-topology` |
| 感知/阶段识别 | `python3 run_perception.py --openai` |
| 构建影子拓扑 | `python3 scripts/build_shadow.py` |
| Honey Agent 初始化 | `python3 run_honey_agent.py` |
| Honey Agent 微调 | `python3 run_honey_agent.py finetune` |
| Trap Agent 全量 | `python3 run_trap_agent.py` |
| Trap Agent 单阶段 | `python3 run_trap_agent.py host` / `interhost` |
| Deception 审计+配置 | `python3 run_deception.py` |
| 影子拓扑 Mininet | `sudo python3 shadow/mininet_shadow.py` |

---

## 推荐工作流
1. **准备企业资产**：填充 `enterprise/`（拓扑 JSON、策略文档等）。
2. **构建影子拓扑**：`python3 scripts/build_shadow.py`
3. **部署蜜罐**：`python3 scripts/manage_hosts.py add h1` → `python3 deployments/h1/run_honeypot.py`
4. **（可选）运行 Mininet**：`sudo python3 shadow/mininet_shadow.py`
5. **生成诱饵/陷阱**：`python3 run_honey_agent.py` → `python3 run_trap_agent.py`
6. **审计与下发配置**：`python3 run_deception.py`（或 `--mode consistency`）
7. **日志感知/摘要**：`python3 run_perception.py --openai`
8. **迭代微调**：根据新情报运行 `python3 run_honey_agent.py finetune`、重复 Trap/Honey 生成。

---

## 配置与自定义
- 协议：`config/{ssh,telnet,http,ftp,mysql}_config.json`
- 虚拟文件系统：`config/filesystem.json`
- 感知规则：`config/perception_rules.json` 或 `perception/rules.py`
- LLM 参数：`HoneyAgentConfig` / `TrapAgentConfig` 的 `openai_model`、温度、top_p

---

## 数据与日志
- `logs/`：蜜罐服务 NDJSON 日志；`deployments/<host>/logs/`：部署独立日志。
- `shadow/`：`shadow_topology.json`、`mininet_shadow.py`、`honey_agent.json`、`trap_agent.json`、`long_memory.json`、`attacker_preferences.json`。

---

## 常见问题
- **Trap/Honey Agent 提示空拓扑**：先运行 `python3 scripts/build_shadow.py` 确保有 `shadow/shadow_topology.json`。
- **OpenAI 调用失败**：检查 API Key/网络/模型；必要时降低 `openai_temperature`。

---

## 贡献与扩展
- 欢迎提交新的协议模拟、规则模板或 Agent 提示词改进。
- 文档和示例的补充同样重要，期待你的经验分享。

> 目标：构建具有持续欺骗能力、易于扩展的 LLM 驱动蜜网。
