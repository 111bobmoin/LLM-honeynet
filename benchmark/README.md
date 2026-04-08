# 多原型对抗性基准测试框架

## 概述

本框架用于评估 LLM Honeynet 对抗自动化渗透工具的防御性能，通过量化指标对比 SOTA 蜜罐系统。

## 支持的渗透工具

| 工具 | 类型 | 特点 |
|------|------|------|
| **PentestGPT** | LLM驱动 | 使用GPT-4生成攻击链，复杂度高 |
| **AutoAttacker** | 自动化 | 暴力破解为主，速度快 |
| **PeaHeal** | 混合型 | 结合启发式和LLM |
| **AutoPT** | LLM驱动 | 高级持续渗透，规避能力强 |

## 评估指标

### 1. 欺骗成功率 (DSR - Deception Success Rate)
```
DSR = (诱饵命中次数 + 陷阱触发次数) / 总攻击次数
```
- **越高越好** - 表示成功欺骗攻击者的比例

### 2. 阶段完成率 (Stage Completion Rate)
攻击链各阶段的完成比例：
- 侦察 (Reconnaissance)
- 立足点 (Foothold)
- 特权提升 (Privilege Escalation)
- 横向移动 (Lateral Movement)
- 数据外泄 (Data Exfiltration)

**越低越好** - 表示有效阻止攻击进展

### 3. 时间到妥协 (TTC - Time to Compromise)
从攻击开始到成功 compromising 目标的时间
- 报告中位数和平均值
- 95% 置信区间

**越长越好** - 表示拖延攻击者的时间

## SOTA 对比系统

| 蜜罐系统 | 类型 | 会议/期刊 | DSR |
|----------|------|-----------|-----|
| **HoneyGPT** | LLM驱动 | USENIX 2023 | 0.42 |
| **DecoyPot** | LLM驱动 | CCS 2024 | 0.51 |
| **ConPot** | 协议特定 | NDSS 2022 | 0.38 |
| **HoneyLLM** | LLM驱动 | IEEE S&P 2024 | 0.47 |
| **Telnet-LM** | 协议特定 | CCS 2023 | 0.35 |

## 快速开始

### 1. 安装依赖

```bash
pip install matplotlib seaborn numpy pandas
```

### 2. 运行基准测试

```bash
# 使用默认参数 (10次实验/工具/场景)
python -m benchmark.run_benchmark

# 自定义参数
python -m benchmark.run_benchmark --experiments 20 --quality 0.75

# 只生成可视化 (使用模拟数据)
python -m benchmark.run_benchmark --visualize-only

# 导出CSV格式数据
python -m benchmark.run_benchmark --export-csv
```

### 3. 查看结果

结果保存在 `benchmark_results/` 目录：

```
benchmark_results/
├── plots/
│   ├── comprehensive_benchmark_heatmap.png   # 综合对比热图
│   ├── improvement_analysis.png                # 改进幅度分析
│   └── tool_performance_heatmap.png            # 工具性能分析
├── benchmark_report_20260317_*.json           # 详细数据
└── benchmark_summary.csv                       # CSV摘要数据
```

## 输出热图说明

### 1. 综合对比热图

包含 4 个子图：
- **DSR对比** - 欺骗成功率相对性能
- **阶段完成率** - 各攻击阶段的防御效果
- **TTC对比** - 时间到妥协对比
- **工具vs蜜罐** - 攻击成功率热图

### 2. 改进分析热图

包含 4 个子图：
- **DSR改进** - 相比SOTA的改进百分比
- **阶段改进** - 各阶段的防御改进率
- **TTC改进** - 时间拖延改进百分比
- **雷达图** - 综合防御能力对比

### 3. 工具性能热图

包含 2 个子图：
- **按工具的DSR** - 各工具的欺骗成功率排序
- **防御成功率** - 各攻击阶段的防御成功率热图

## 测试场景

### 场景 1: 企业网络-外网入口
- 模拟企业网络边界
- DMZ区和对外服务
- 诱饵: 开发服务器、管理门户、备份服务器

### 场景 2: 内网横向移动
- 内网环境测试
- 诱饵: 备份文件服务器、数据库副本、域控制器

### 场景 3: 数据库渗透
- 数据库专项测试
- 诱饵: 从库、报表库、缓存服务器

## 真实测试环境集成

要使用真实渗透测试环境，需要：

1. 配置测试目标系统
2. 集成渗透工具 API:
   - PentestGPT: OpenAI API key
   - AutoAttacker: Metasploit框架集成
   - PeaHeal: 工具API接口
   - AutoPT: 渗透工具配置

3. 修改 `simulate_experiment()` 函数，替换为真实调用

## 数据格式

### 实验结果 JSON

```json
{
  "timestamp": "2026-03-17T12:00:00",
  "total_experiments": 120,
  "overall_metrics": {
    "dsr": 0.658,
    "stage_completion": {
      "recon": 0.890,
      "foothold": 0.665,
      "priv_esc": 0.448,
      "lateral": 0.290,
      "exfil": 0.160
    },
    "ttc_mean": 1315.0,
    "ttc_median": 1250.0,
    "ttc_ci": [1080.0, 1550.0]
  },
  "by_tool": {
    "PentestGPT": {
      "dsr": 0.68,
      "experiments": 30,
      ...
    },
    ...
  },
  "sota_comparison": {
    "HoneyGPT": {
      "dsr_improvement": 47.6,
      "ttc_improvement": 15.3,
      ...
    },
    ...
  }
}
```

## 扩展

### 添加新的渗透工具

```python
from benchmark import DeceptionTool, AttackStage

# 在 DeceptionTool 枚举中添加新工具
# 然后运行测试
```

### 添加新的测试场景

```python
from benchmark import TestScenario, AttackStage

new_scenario = TestScenario(
    name="新场景",
    description="场景描述",
    topology={...},
    real_assets=[...],
    decoy_assets=[...],
    trap_chains=[...],
    expected_attack_path=[...]
)

benchmark.add_scenario(new_scenario)
```

### 添加新的 SOTA 对比

在 `sota_honeypots` 字典中添加新系统数据。

## 引用

如果使用本框架，请引用：

```
@inproceedings{llm-honeynet-2026,
  title={LLM Honeynet: Multi-Prototype Adversarial Benchmarking Framework},
  author={Your Name},
  booktitle={Proceedings of the ... Conference},
  year={2026}
}
```

## 许可证

与主项目保持一致。
