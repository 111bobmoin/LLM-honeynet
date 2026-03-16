# LLM Honeynet Web Interface

## 概述

这是一个为 LLM Honeynet 项目设计的 Web 前端界面，提供了可视化的操作面板来管理感知、编排和欺骗三个核心阶段。

## 功能

### 📊 概览 (Dashboard)
- 系统状态概览
- 部署主机统计
- 操作记录统计
- 阶段状态监控
- 快速操作入口

### 👁️ 感知 (Perception)
- 查看可用主机
- 选择目标进行分析
- 配置 OpenAI 智能摘要
- 查看分析结果和攻击阶段

### 🎯 编排 (Orchestration)
- **Honey Agent**: 生成端口、文件和漏洞诱饵
- **Trap Agent**: 生成主机内闭环和跨主机陷阱链
- 攻击者偏好设置
- 编排状态监控

### 🎭 欺骗 (Deception)
- 一致性审计
- 配置文件生成
- 部署主机管理
- 完整流程执行

### ⚙️ 操作记录 (Operations)
- 查看所有操作历史
- 操作状态追踪
- 详细结果查看

### 💾 影子数据 (Shadow Data)
- 影子文件状态
- 数据详情查看
- Honey/Trap Agent 结果

## 安装

### 1. 安装依赖

```bash
pip install -r web/requirements.txt
```

### 2. 配置 OpenAI API Key

确保 `secrets/openai_api_key.txt` 文件存在并包含有效的 API key:

```
sk-...
```

## 使用

### 启动 Web 服务

```bash
python run_web.py
```

服务将在 `http://localhost:5000` 启动。

### 访问界面

打开浏览器访问 `http://localhost:5000`

## 目录结构

```
web/
├── api.py              # Flask API 服务器
├── static/
│   ├── index.html      # 主页面
│   ├── styles.css      # 样式文件
│   └── app.js          # 前端逻辑
└── requirements.txt    # Python 依赖
```

## API 端点

### 概览
- `GET /api/health` - 健康检查
- `GET /api/dashboard/summary` - 仪表盘摘要

### 感知
- `GET /api/perception/hosts` - 获取可用主机
- `POST /api/perception/analyze` - 运行感知分析

### 编排
- `GET /api/orchestrate/status` - 获取编排状态
- `POST /api/orchestrate/honey` - 运行 Honey Agent
- `POST /api/orchestrate/trap` - 运行 Trap Agent

### 欺骗
- `POST /api/deception/run` - 运行欺骗代理
- `GET /api/deception/consistency` - 获取一致性报告
- `GET /api/deployment/hosts` - 获取部署主机

### 操作
- `GET /api/operations` - 获取操作列表
- `GET /api/operations/<id>` - 获取操作详情

### 配置
- `GET /api/config/topology` - 获取拓扑配置
- `GET /api/config/preferences` - 获取攻击者偏好
- `POST /api/config/preferences` - 更新攻击者偏好

### 影子数据
- `GET /api/shadow/data` - 获取影子数据

## 工作流程

### 完整工作流

1. **感知分析**
   - 导航到"感知"页面
   - 选择要分析的主机
   - (可选) 启用 OpenAI 智能摘要
   - 点击"开始分析"

2. **生成诱饵**
   - 导航到"编排"页面
   - 运行 Honey Agent 生成端口/文件/漏洞诱饵
   - (可选) 设置攻击者偏好
   - 运行 Trap Agent 生成陷阱链

3. **配置欺骗**
   - 导航到"欺骗"页面
   - 运行一致性审计
   - 生成部署配置
   - 或直接运行"完整流程"

## 注意事项

1. **OpenAI API**: 使用 LLM 功能需要有效的 OpenAI API key
2. **文件权限**: 确保 web 服务器有读写 `shadow/` 目录的权限
3. **端口占用**: 默认使用 5000 端口，如需修改请编辑 `web/api.py`

## 开发

### 修改 API 端口

编辑 `web/api.py` 文件最后一行:

```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

### 自定义样式

所有样式定义在 `web/static/styles.css` 中，使用 CSS 变量方便主题定制。
