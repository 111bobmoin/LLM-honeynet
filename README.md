# LLM Honeynet 平台

基于 OpenAI 的自动化蜜网平台，覆盖感知、编排、欺骗和影子网络四层能力。项目可以从蜜罐日志中提取攻击者偏好，生成影子拓扑、诱饵数据与部署配置，并在 Mininet 中拉起影子蜜网，同时启动每个节点对应的 honeypot 服务。

![OpenAI](https://img.shields.io/badge/LLM-OpenAI-blue)
![Flask](https://img.shields.io/badge/Web-Flask-3.0-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)

## 功能概览

- 感知层 `perception`
  - 分析 `deployments/<host>/logs` 中的日志
  - 识别攻击阶段
  - 调用 OpenAI 生成攻击者行为偏好
  - 基于 `enterprise/enterprise_topology.json` 生成 `shadow/shadow_topology.json`
- 编排层 `orchestrator`
  - `Honey Agent` 生成端口、文件、漏洞诱饵
  - `Trap Agent` 生成主机内 trap loop 和跨主机 credential chain
- 欺骗层 `deception`
  - 运行一致性检测
  - 为每个主机生成独立的 deployment 配置
- 运行层 `honeypot + mininet`
  - `run_honeypot.py --deployment <host>` 单独启动某个节点
  - `shadow/mininet_shadow.py` 启动影子拓扑
  - `shadow/mininet_shadow.py --start-honeypots` 在 Mininet 内自动拉起每个节点的 honeypot

## 当前目录职责

```text
llm_honeynet/
├── perception/              # 感知分析与偏好总结
├── orchestrator/            # Honey / Trap Agent 与 shadow topology 生成
├── deception/               # 一致性检测与 deployment 配置生成
├── honeypot/                # SSH / Telnet / FTP / HTTP / HTTPS / MySQL / PostgreSQL / RDP
├── shadow/                  # 影子侧产物：preferences / topology / memory / mininet script
├── deployments/             # 每个主机的独立配置、日志与运行时输出
├── enterprise/              # 企业网络原始拓扑
├── config/                  # 基础模板配置
├── web/                     # Flask Web UI
├── run_perception.py
├── run_honey_agent.py
├── run_trap_agent.py
├── run_deception.py
├── run_honeypot.py
└── run_full_pipeline.py
```

## 环境要求

### Python 依赖

```bash
pip install -r requirements.txt
pip install asyncssh
```

### OpenAI Key

```bash
mkdir -p secrets
echo "YOUR_OPENAI_KEY" > secrets/openai_api_key.txt
```

### Mininet 依赖

如果需要启动影子网络，需要系统已安装：

- `mininet`
- `openvswitch`
- 对应的 root 权限 / sudo 环境

快速自检：

```bash
python3 -c "import mininet; print('mininet-ok')"
```

## 推荐使用方式

### 1. 一键跑完整流程

这会依次执行：

1. `perception`
2. `Honey Agent`
3. `Trap Agent`
4. `Deception`
5. `Mininet shadow network`
6. 在每个影子节点内启动对应 honeypot

无交互短时测试：

```bash
python3 run_full_pipeline.py --openai --network-no-cli --network-duration 10
```

交互式长期运行：

```bash
python3 run_full_pipeline.py --openai
```

### 2. 分阶段运行

感知：

```bash
python3 run_perception.py --openai
```

编排：

```bash
python3 run_honey_agent.py --mode initialization
python3 run_trap_agent.py all
```

欺骗：

```bash
python3 run_deception.py --mode full
```

仅启动影子网络：

```bash
python3 shadow/mininet_shadow.py --topology shadow/shadow_topology.json
```

启动影子网络并自动拉起各节点 honeypot：

```bash
python3 shadow/mininet_shadow.py \
  --topology shadow/shadow_topology.json \
  --start-honeypots \
  --project-root .
```

无交互短时测试：

```bash
python3 shadow/mininet_shadow.py \
  --topology shadow/shadow_topology.json \
  --start-honeypots \
  --project-root . \
  --no-cli \
  --duration 10
```

### 3. 单独启动某个 deployment

```bash
python3 run_honeypot.py --deployment app-01
python3 run_honeypot.py --deployment bastion-01
python3 run_honeypot.py --deployment db-01
```

只启动某些服务：

```bash
python3 run_honeypot.py --deployment app-01 --services http,https
python3 run_honeypot.py --deployment db-01 --services mysql,postgresql
```

## 关键产物

### 感知层输出

- `shadow/attacker_preferences.json`
- `shadow/shadow_topology.json`
- `shadow/mininet_shadow.py`

### 编排层输出

- `shadow/honey_agent.json`
- `shadow/trap_agent.json`

### 欺骗层输出

- `shadow/deception_consistency_report.json`
- `deployments/<host>/config/*.json`
- `deployments/<host>/deception_notes.json`

### 运行层输出

- `deployments/<host>/logs/*.log`
- `deployments/<host>/logs/honeypot_runtime.log`

## 实际支持的服务

当前 `honeypot` 运行时支持：

- `ssh`
- `telnet`
- `ftp`
- `http`
- `https`
- `mysql`
- `postgresql`
- `rdp`

`run_honeypot.py --services` 也只接受这些服务名。

## 常用命令

查看全流程帮助：

```bash
python3 run_full_pipeline.py --help
```

查看感知入口帮助：

```bash
python3 run_perception.py --help
```

查看单节点 honeypot 帮助：

```bash
python3 run_honeypot.py --help
```

查看影子网络帮助：

```bash
python3 shadow/mininet_shadow.py --help
```

启动 Web：

```bash
python3 run_web.py
```

## 运行注意事项

- `run_perception.py` 负责生成 `shadow_topology.json`，但不负责启动 Mininet。
- `shadow/mininet_shadow.py` 负责单独启动影子网络。
- `run_full_pipeline.py` 会在最后调用 `shadow/mininet_shadow.py --start-honeypots`。
- 同一台宿主机直接同时启动多个 deployment 时，可能存在端口冲突；通过 Mininet host namespace 运行时，这个问题被隔离。
- 如果 HTTPS 启动失败，检查 `certs/honeypot.crt` 和 `certs/honeypot.key` 是否存在。
- 如果 SSH 启动失败，检查 `asyncssh` 是否已安装。
- 如果 Mininet 启动失败，优先检查 `mininet`、`ovs-vsctl`、root 权限和内核网络环境。

## 当前推荐验证路径

最小链路验证：

```bash
python3 run_perception.py --openai
python3 run_honey_agent.py --mode initialization
python3 run_trap_agent.py all
python3 run_deception.py --mode full
python3 shadow/mininet_shadow.py --topology shadow/shadow_topology.json --start-honeypots --project-root . --no-cli --duration 5
```

或者直接：

```bash
python3 run_full_pipeline.py --openai --network-no-cli --network-duration 5
```

## Web API

Web 入口在 `web/api.py`，当前主要覆盖：

- 感知分析
- Honey Agent
- Trap Agent
- Deception
- Deployment 视图
- Shadow 数据视图

启动：

```bash
python3 web/api.py
```

## 许可证

MIT License
