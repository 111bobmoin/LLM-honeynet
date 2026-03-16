# LLM Honeynet 平台

基于大语言模型的智能蜜网平台，集成多协议高仿真蜜罐、阶段化入侵感知、自动化诱饵生成与 Web 管理界面。

![GLM](https://img.shields.io/badge/LLM-GLM--4--Flash-blue)
![Flask](https://img.shields.io/badge/Web-Flask-3.0-green)
![Python](https://img.shields.io/badge/Python-3.10+-yellow)

---

## 核心特性

### 三阶段自动化流程
- **感知 (Perception)**：分析蜜罐日志，识别攻击阶段 (Stage 1-5)
- **编排 (Orchestration)**：Honey Agent 生成端口/文件/漏洞诱饵，Trap Agent 生成陷阱链
- **欺骗 (Deception)**：一致性审计并生成部署配置

### 智能诱饵生成
- **Honey Agent**：基于 GLM 生成真实感的端口、文件和漏洞配置
- **Trap Agent**：创建主机内文件闭环和跨主机凭证链
- **Attacker Preferences**：学习和适应攻击者行为模式

### Web 管理界面
- **实时仪表板**：监控所有阶段的状态和操作
- **可视化展示**：影子数据、陷阱环、凭证链的图形化展示
- **一键操作**：通过 Web UI 运行完整的欺骗流程

---

## 快速开始

### 环境要求
```bash
Python 3.10+
```

### 安装依赖

```bash
# 安装 Python 包
pip install -r requirements.txt

# 配置 GLM API Key
# 从 https://open.bigmodel.cn/usercenter/apikeys 获取
mkdir -p secrets
echo "your_api_key_here" > secrets/glm_api_key.txt
```

### 启动 Web 服务器

```bash
# 方法 1：使用启动脚本
python3 run_web.py

# 方法 2：直接运行
python3 web/api.py
```

访问：http://localhost:5000

---

## 目录结构

```
llm_honeynet/
├── llm/                    # GLM API 客户端
│   └── glm_client.py      # 智谱 AI API 封装
├── perception/             # 感知模块
│   ├── analyzer.py        # 日志分析与阶段识别
│   └── glm_summary.py     # GLM 摘要生成
├── orchestrator/          # 编排模块
│   ├── honey_agent.py     # 诱饵生成 Agent
│   ├── trap_agent.py      # 陷阱生成 Agent
│   └── memory.py          # 短期/长期记忆管理
├── deception/             # 欺骗模块
│   └── agent.py           # 一致性审计与配置生成
├── web/                   # Web 前端
│   ├── static/            # HTML/CSS/JS
│   └── api.py             # Flask REST API
├── shadow/                # 影子数据存储
│   ├── honey_agent.json   # Honey Agent 输出
│   ├── trap_agent.json    # Trap Agent 输出
│   ├── long_memory.json   # 长期记忆
│   └── attacker_preferences.json  # 攻击者偏好
├── deployments/           # 蜜罐部署目录
├── config/                # 配置模板
├── logs/                  # 蜜罐日志
└── secrets/               # 敏感信息（API Key）
```

---

## 使用指南

### Web 界面操作

#### 1. 感知分析
- 导航到 **感知** 页面
- 选择目标主机
- 点击 **开始分析** 识别攻击阶段

#### 2. 运行 Honey Agent
- 导航到 **编排** 页面
- 选择运行模式（初始化/微调）
- 配置 GLM 模型参数
- 点击 **运行 Honey Agent**

#### 3. 运行 Trap Agent
- 选择运行模式（完整流程/仅主机内/仅跨主机）
- 配置参数
- 点击 **运行 Trap Agent**

#### 4. 配置欺骗
- 导航到 **欺骗** 页面
- 运行一致性审计
- 生成部署配置

### 命令行操作

```bash
# 运行感知分析
python3 -c "
from perception import analyze_host, load_rules
from pathlib import Path
rules = load_rules(Path('config'))
analysis = analyze_host('test-host', Path('logs'), rules)
print(f'Max stage: {analysis.max_stage}')
"

# 运行 Honey Agent
python3 -c "
from orchestrator import HoneyAgent, HoneyAgentConfig
from pathlib import Path

config = HoneyAgentConfig(
    short_memory_path=Path('shadow/honey_agent.json'),
    glm_key_path=Path('secrets/glm_api_key.txt'),
    glm_model='glm-4-flash'
)

agent = HoneyAgent(config)
result = agent.run_initialization()
print(f'Generated {len(result[\"short_memory\"])} hosts')
"

# 运行 Trap Agent
python3 -c "
from orchestrator import TrapAgent, TrapAgentConfig
from pathlib import Path

config = TrapAgentConfig(
    short_memory_path=Path('shadow/honey_agent.json'),
    trap_memory_path=Path('shadow/trap_agent.json'),
    glm_key_path=Path('secrets/glm_api_key.txt')
)

agent = TrapAgent(config)
result = agent.run_full_pipeline()
print(f'Generated trap chains for {len(result[\"hosts\"])} hosts')
"

# 运行 Deception Agent
python3 -c "
from deception import DeceptionAgent, DeceptionAgentConfig
from pathlib import Path

config = DeceptionAgentConfig(
    deployments_root=Path('deployments'),
    short_memory_path=Path('shadow/honey_agent.json'),
    trap_memory_path=Path('shadow/trap_agent.json'),
    glm_key_path=Path('secrets/glm_api_key.txt')
)

agent = DeceptionAgent(config)

# 一致性审计
report = agent.run_consistency_check()
print(f'Issues found: {len(report.get(\"issues\", []))}')

# 生成配置
configs = agent.generate_host_configs()
print(f'Generated configs for {len(configs)} hosts')
"
```

---

## API 文档

### REST API 端点

| 端点 | 方法 | 描述 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/dashboard/summary` | GET | 仪表板概览 |
| `/api/perception/hosts` | GET | 获取可用主机 |
| `/api/perception/analyze` | POST | 运行感知分析 |
| `/api/orchestrate/honey` | POST | 运行 Honey Agent |
| `/api/orchestrate/trap` | POST | 运行 Trap Agent |
| `/api/orchestrate/status` | GET | 获取编排状态 |
| `/api/deception/run` | POST | 运行 Deception Agent |
| `/api/deception/consistency` | GET | 获取一致性报告 |
| `/api/deployment/hosts` | GET | 获取部署主机列表 |
| `/api/shadow/data` | GET | 获取影子数据 |
| `/api/config/preferences` | GET/POST | 管理攻击者偏好 |

### 请求示例

```bash
# 运行 Honey Agent
curl -X POST http://localhost:5000/api/orchestrate/honey \
  -H "Content-Type: application/json" \
  -d '{"mode": "initialization"}'

# 运行 Trap Agent
curl -X POST http://localhost:5000/api/orchestrate/trap \
  -H "Content-Type: application/json" \
  -d '{"mode": "all"}'

# 运行完整欺骗流程
curl -X POST http://localhost:5000/api/deception/run \
  -H "Content-Type: application/json" \
  -d '{"mode": "full", "hosts": "h1,h2,h3"}'
```

---

## 配置说明

### GLM 模型配置

```python
from llm import GLMClient, GLMClientConfig

config = GLMClientConfig(
    api_key_path=Path("secrets/glm_api_key.txt"),
    model="glm-4-flash",      # 可选: glm-4, glm-4-plus
    temperature=0.1,
    top_p=0.9,
    max_tokens=4096
)
```

### Agent 配置

**Honey Agent:**
```python
HoneyAgentConfig(
    glm_model="glm-4-flash",
    glm_temperature=0.1,
    glm_top_p=0.9,
    glm_max_tokens=4096
)
```

**Trap Agent:**
```python
TrapAgentConfig(
    glm_model="glm-4-flash",
    glm_temperature=0.15,
    glm_top_p=0.85,
    glm_max_tokens=4096
)
```

**Deception Agent:**
```python
DeceptionAgentConfig(
    glm_model="glm-4-flash",
    glm_temperature=0.1,
    glm_top_p=0.9,
    glm_max_tokens=8192  # 配置生成需要更多 token
)
```

---

## 数据格式

### Honey Agent 输出

```json
{
  "hosts": [
    {
      "name": "bastion-01",
      "ports": [
        {
          "port": 22,
          "service": "SSH",
          "files": [
            {"path": "/root/.ssh/authorized_keys"},
            {"path": "/etc/ssh/sshd_config"}
          ],
          "vulnerabilities": [
            {
              "type": "weak credentials",
              "target_port": 22
            }
          ]
        }
      ]
    }
  ]
}
```

### Trap Agent 输出

```json
{
  "hosts": [
    {
      "name": "bastion-01",
      "host_loops": [
        ["/etc/passwd", "/var/log/auth.log", "/root/.ssh/id_rsa"]
      ]
    }
  ],
  "chains": [
    {
      "name": "lateral-chain-1",
      "steps": [
        {"host": "bastion-01", "tier": "low"},
        {"host": "app-01", "tier": "mid"},
        {"host": "bastion-01", "tier": "low"}
      ]
    }
  ]
}
```

---

## 常见问题

### Q: GLM API 调用失败？
**A:** 检查以下项：
1. API Key 是否正确配置在 `secrets/glm_api_key.txt`
2. 网络连接是否正常
3. API 额度是否充足

### Q: 配置生成返回空结果？
**A:**
1. 确保 Honey Agent 和 Trap Agent 已成功运行
2. 检查 `shadow/` 目录下是否有生成的 JSON 文件
3. 增加 `glm_max_tokens` 参数值

### Q: 如何查看生成的配置？
**A:**
1. 访问 **欺骗** 页面查看部署主机列表
2. 查看 `deployments/<host>/config/` 目录下的配置文件
3. 访问 **影子数据** 页面查看可视化数据

### Q: Web 服务器端口冲突？
**A:** 修改 `web/api.py` 最后一行的端口：
```python
app.run(host='0.0.0.0', port=5001, debug=True)
```

---

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Web Frontend                         │
│                  (Dashboard + Controls)                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      Flask REST API                         │
│                      /web/api.py                            │
└─────┬─────────────┬─────────────┬──────────────────────────┘
      │             │             │
      ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌────────────┐
│Perception│  │Orchestrat│  │ Deception  │
│  Module  │  │   or     │  │   Module   │
└─────┬────┘  └────┬─────┘  └──────┬─────┘
      │            │                │
      └────────────┴────────────────┘
                   │
                   ▼
          ┌────────────────┐
          │  GLM Client    │
          │ (zhipuai SDK)  │
          └────────────────┘
                   │
                   ▼
          ┌────────────────┐
          │ GLM-4-Flash    │
          │   (智谱 AI)     │
          └────────────────┘
```

---

## 开发计划

- [ ] 支持更多 LLM 提供商
- [ ] 添加实时日志流展示
- [ ] 支持多租户管理
- [ ] 添加攻击行为可视化图表
- [ ] 支持自定义协议插件

---

## 许可证

MIT License

---

## 致谢

- [智谱 AI](https://open.bigmodel.cn/) - 提供 GLM-4 大语言模型 API
- 原项目架构设计者

---

**目标**：构建具有持续欺骗能力、易于扩展的 LLM 驱动蜜网平台
