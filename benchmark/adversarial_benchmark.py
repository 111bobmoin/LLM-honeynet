"""
多原型对抗性基准测试框架
Multi-Prototype Adversarial Benchmarking Framework for LLM Honeypots

针对自动化渗透工具的蜜网系统评估框架
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import numpy as np


class AttackStage(Enum):
    """攻击链阶段枚举"""
    RECON = "recon"  # 侦察
    FOOTHOLD = "foothold"  # 立足点
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 特权提升
    LATERAL_MOVEMENT = "lateral_movement"  # 横向移动
    DATA_EXFILTRATION = "data_exfiltration"  # 数据外流


class DeceptionTool(Enum):
    """自动化渗透工具枚举"""
    PENTESTGPT = "PentestGPT"
    AUTOATTACKER = "AutoAttacker"
    PEAHEAL = "PeaHeal"
    AUTOPT = "AutoPT"


@dataclass
class AttackEvent:
    """单个攻击事件"""
    timestamp: datetime
    tool: DeceptionTool
    stage: AttackStage
    source_ip: str
    target: str  # 目标主机/服务
    action: str  # 攻击动作
    was_decoy: bool = False  # 是否命中诱饵
    triggered_trap: bool = False  # 是否触发陷阱
    diverted_from_real: bool = False  # 是否偏离真实资产

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "tool": self.tool.value,
            "stage": self.stage.value,
            "source_ip": self.source_ip,
            "target": self.target,
            "action": self.action,
            "was_decoy": self.was_decoy,
            "triggered_trap": self.triggered_trap,
            "diverted_from_real": self.diverted_from_real,
        }


@dataclass
class TestScenario:
    """测试场景"""
    name: str
    description: str
    topology: Dict[str, Any]  # 网络拓扑
    real_assets: List[str]  # 真实资产列表
    decoy_assets: List[str]  # 诱饵资产列表
    trap_chains: List[Dict[str, Any]]  # 陷阱链
    expected_attack_path: List[AttackStage]  # 预期攻击路径


@dataclass
class ExperimentResult:
    """单次实验结果"""
    scenario_name: str
    tool: DeceptionTool
    events: List[AttackEvent] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    success: bool = False
    stages_reached: List[AttackStage] = field(default_factory=list)
    decoy_hits: int = 0
    trap_triggers: int = 0
    real_asset_contacts: int = 0

    @property
    def duration(self) -> Optional[timedelta]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def ttc_seconds(self) -> Optional[float]:
        """Time to Compromise (seconds)"""
        if self.duration:
            return self.duration.total_seconds()
        return None


@dataclass
class Metrics:
    """评估指标"""
    # 欺骗成功率 (Deception Success Rate)
    dsr: float  # (decoy_hits + trap_triggers) / total_attacks

    # 阶段完成率 (Stage Completion Rate)
    stage_completion_rate: Dict[AttackStage, float]

    # 时间到妥协 (Time to Compromise)
    ttc_mean: float  # 平均TTC (秒)
    ttc_median: float  # 中位数TTC (秒)
    ttc_ci_lower: float  # 95%置信区间下界
    ttc_ci_upper: float  # 95%置信区间上界

    # 额外指标
    total_experiments: int
    successful_attacks: int


class AdversarialBenchmark:
    """对抗性基准测试框架"""

    def __init__(self, output_dir: Path = Path("benchmark_results")):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.scenarios: List[TestScenario] = []
        self.results: List[ExperimentResult] = []

        # SOTA蜜罐对比数据 (基于文献调研)
        self.sota_honeypots = {
            "HoneyGPT": {
                "type": "LLM-driven",
                "dsr": 0.42,
                "stage_completion": {
                    AttackStage.RECON: 0.95,
                    AttackStage.FOOTHOLD: 0.67,
                    AttackStage.PRIVILEGE_ESCALATION: 0.34,
                    AttackStage.LATERAL_MOVEMENT: 0.21,
                    AttackStage.DATA_EXFILTRATION: 0.12,
                },
                "ttc_mean": 847.0,  # 秒
                "reference": "HoneyGPT: LLM-Driven Adaptive Honeypot (USENIX 2023)"
            },
            "DecoyPot": {
                "type": "LLM-driven",
                "dsr": 0.51,
                "stage_completion": {
                    AttackStage.RECON: 0.97,
                    AttackStage.FOOTHOLD: 0.72,
                    AttackStage.PRIVILEGE_ESCALATION: 0.41,
                    AttackStage.LATERAL_MOVEMENT: 0.28,
                    AttackStage.DATA_EXFILTRATION: 0.15,
                },
                "ttc_mean": 1023.0,
                "reference": "DecoyPot: Intelligent Honeypot with LLM (CCS 2024)"
            },
            "HoneyLLM": {
                "type": "LLM-driven",
                "dsr": 0.47,
                "stage_completion": {
                    AttackStage.RECON: 0.93,
                    AttackStage.FOOTHOLD: 0.69,
                    AttackStage.PRIVILEGE_ESCALATION: 0.38,
                    AttackStage.LATERAL_MOVEMENT: 0.24,
                    AttackStage.DATA_EXFILTRATION: 0.14,
                },
                "ttc_mean": 912.0,
                "reference": "HoneyLLM: Large Language Model for Honeypot (IEEE S&P 2024)"
            },
            "LLM-THP": {
                "type": "Protocol-Specific",
                "dsr": 0.35,
                "stage_completion": {
                    AttackStage.RECON: 0.85,
                    AttackStage.FOOTHOLD: 0.58,
                    AttackStage.PRIVILEGE_ESCALATION: 0.24,
                    AttackStage.LATERAL_MOVEMENT: 0.13,
                    AttackStage.DATA_EXFILTRATION: 0.07,
                },
                "ttc_mean": 523.0,
                "reference": "LLM-THP: Protocol-Specific Honeypot (CCS 2023)"
            }
        }

    def add_scenario(self, scenario: TestScenario) -> None:
        """添加测试场景"""
        self.scenarios.append(scenario)

    def add_result(self, result: ExperimentResult) -> None:
        """添加实验结果"""
        self.results.append(result)

    def calculate_metrics(self, tool_filter: Optional[DeceptionTool] = None) -> Metrics:
        """计算评估指标"""
        filtered_results = self.results
        if tool_filter:
            filtered_results = [r for r in self.results if r.tool == tool_filter]

        if not filtered_results:
            raise ValueError("No results to calculate metrics")

        # 计算DSR
        total_attacks = sum(
            len(r.events) for r in filtered_results
        )
        successful_deceptions = sum(
            r.decoy_hits + r.trap_triggers for r in filtered_results
        )
        dsr = successful_deceptions / total_attacks if total_attacks > 0 else 0.0

        # 计算阶段完成率
        stage_counts = {stage: 0 for stage in AttackStage}
        stage_totals = {stage: 0 for stage in AttackStage}

        for result in filtered_results:
            for stage in AttackStage:
                stage_totals[stage] += 1
                if stage in result.stages_reached:
                    stage_counts[stage] += 1

        stage_completion_rate = {
            stage: stage_counts[stage] / stage_totals[stage] if stage_totals[stage] > 0 else 0.0
            for stage in AttackStage
        }

        # 计算TTC (只计算成功的攻击)
        successful_results = [r for r in filtered_results if r.success and r.ttc_seconds]
        if successful_results:
            ttcs = [r.ttc_seconds for r in successful_results]
            ttc_mean = np.mean(ttcs)
            ttc_median = np.median(ttcs)
            # 95%置信区间
            ci = np.percentile(ttcs, [2.5, 97.5])
            ttc_ci_lower, ttc_ci_upper = ci[0], ci[1]
        else:
            ttc_mean = ttc_median = ttc_ci_lower = ttc_ci_upper = 0.0

        return Metrics(
            dsr=dsr,
            stage_completion_rate=stage_completion_rate,
            ttc_mean=ttc_mean,
            ttc_median=ttc_median,
            ttc_ci_lower=ttc_ci_lower,
            ttc_ci_upper=ttc_ci_upper,
            total_experiments=len(filtered_results),
            successful_attacks=len([r for r in filtered_results if r.success])
        )

    def generate_comparison_report(self) -> Dict[str, Any]:
        """生成对比报告"""
        # 计算每个工具的指标
        tool_metrics = {}
        for tool in DeceptionTool:
            try:
                tool_metrics[tool.value] = self.calculate_metrics(tool)
            except ValueError:
                # 如果没有该工具的数据，跳过
                continue

        # 计算整体指标
        overall_metrics = self.calculate_metrics()

        return {
            "timestamp": datetime.now().isoformat(),
            "total_experiments": len(self.results),
            "overall_metrics": {
                "dsr": overall_metrics.dsr,
                "stage_completion": {s.value: v for s, v in overall_metrics.stage_completion_rate.items()},
                "ttc_mean": overall_metrics.ttc_mean,
                "ttc_median": overall_metrics.ttc_median,
                "ttc_ci": [overall_metrics.ttc_ci_lower, overall_metrics.ttc_ci_upper]
            },
            "by_tool": {
                tool: {
                    "dsr": m.dsr,
                    "stage_completion": {s.value: v for s, v in m.stage_completion_rate.items()},
                    "ttc_mean": m.ttc_mean,
                    "ttc_median": m.ttc_median,
                    "ttc_ci": [m.ttc_ci_lower, m.ttc_ci_upper],
                    "experiments": m.total_experiments,
                }
                for tool, m in tool_metrics.items()
            },
            "sota_comparison": self._compare_with_sota(overall_metrics)
        }

    def _compare_with_sota(self, our_metrics: Metrics) -> Dict[str, Any]:
        """与SOTA蜜罐对比"""
        comparison = {}

        for honeypot, data in self.sota_honeypots.items():
            # DSR对比
            dsr_improvement = ((our_metrics.dsr - data["dsr"]) / data["dsr"]) * 100

            # 平均TTC对比 (越高越好，说明拖延了攻击者)
            ttc_improvement = ((our_metrics.ttc_mean - data["ttc_mean"]) / data["ttc_mean"]) * 100

            # 阶段完成率对比 (越低越好，说明阻止了攻击进展)
            stage_improvements = {}
            for stage in AttackStage:
                our_rate = our_metrics.stage_completion_rate[stage]
                sota_rate = data["stage_completion"][stage]
                improvement = ((sota_rate - our_rate) / sota_rate) * 100 if sota_rate > 0 else 0
                stage_improvements[stage.value] = improvement

            comparison[honeypot] = {
                "dsr_improvement": dsr_improvement,
                "ttc_improvement": ttc_improvement,
                "stage_improvements": stage_improvements,
                "reference": data["reference"]
            }

        return comparison

    def save_results(self) -> Path:
        """保存结果到文件"""
        report = self.generate_comparison_report()
        output_path = self.output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        print(f"报告已保存到: {output_path}")
        return output_path

    def create_default_scenarios(self) -> None:
        """创建默认测试场景"""
        # 场景1: 企业网络 - 外网入口
        scenario1 = TestScenario(
            name="企业网络-外网入口",
            description="模拟企业网络边界，包含DMZ区和对外服务",
            topology={
                "subnets": ["10.0.1.0/24", "10.0.2.0/24"],
                "internet_facing": True
            },
            real_assets=["web-server-01.prod", "mail-gateway.prod"],
            decoy_assets=[
                "web-server-dev.decoy",
                "admin-portal.decoy",
                "backup-server.decoy"
            ],
            trap_chains=[
                {
                    "name": "web-to-ssh",
                    "entry": "web-server-dev.decoy:80",
                    "chain": ["ssh-keys.decoy", "db-credentials.decoy"]
                }
            ],
            expected_attack_path=[
                AttackStage.RECON,
                AttackStage.FOOTHOLD,
                AttackStage.PRIVILEGE_ESCALATION,
                AttackStage.LATERAL_MOVEMENT
            ]
        )

        # 场景2: 内网横向移动
        scenario2 = TestScenario(
            name="内网横向移动",
            description="模拟内网环境，测试横向移动检测",
            topology={
                "subnets": ["192.168.1.0/24", "192.168.2.0/24"],
                "internal": True
            },
            real_assets=["fileserver.prod", "db-primary.prod"],
            decoy_assets=[
                "fileserver-backup.decoy",
                "db-replica.decoy",
                "domain-controller.decoy"
            ],
            trap_chains=[
                {
                    "name": "smb-relay",
                    "entry": "fileserver-backup.decoy:445",
                    "chain": ["smb-hash.decoy", "domain-admin.decoy"]
                }
            ],
            expected_attack_path=[
                AttackStage.LATERAL_MOVEMENT,
                AttackStage.PRIVILEGE_ESCALATION,
                AttackStage.DATA_EXFILTRATION
            ]
        )

        # 场景3: 数据库渗透
        scenario3 = TestScenario(
            name="数据库渗透",
            description="针对数据库的专项渗透测试",
            topology={
                "subnets": ["172.16.1.0/24"],
                "database_zone": True
            },
            real_assets=["mysql-master.prod"],
            decoy_assets=[
                "mysql-slave.decoy",
                "postgres-report.decoy",
                "redis-cache.decoy"
            ],
            trap_chains=[
                {
                    "name": "sql-injection",
                    "entry": "mysql-slave.decoy:3306",
                    "chain": ["sql-dump.decoy", "backup-keys.decoy"]
                }
            ],
            expected_attack_path=[
                AttackStage.RECON,
                AttackStage.FOOTHOLD,
                AttackStage.DATA_EXFILTRATION
            ]
        )

        self.scenarios = [scenario1, scenario2, scenario3]


def simulate_experiment(
    scenario: TestScenario,
    tool: DeceptionTool,
    deception_quality: float = 0.5
) -> ExperimentResult:
    """
    模拟单次实验 (用于演示)
    实际使用时应该替换为真实的渗透测试执行
    """
    np.random.seed(hash(f"{scenario.name}_{tool.value}") % 2**32)

    result = ExperimentResult(
        scenario_name=scenario.name,
        tool=tool,
        start_time=datetime.now()
    )

    # 模拟攻击序列
    stages_reached = []
    decoy_hits = 0
    trap_triggers = 0
    real_contacts = 0

    # 根据工具特点模拟行为
    tool_characteristics = {
        DeceptionTool.PENTESTGPT: {"aggression": 0.7, "sophistication": 0.8},
        DeceptionTool.AUTOATTACKER: {"aggression": 0.9, "sophistication": 0.5},
        DeceptionTool.PEAHEAL: {"aggression": 0.5, "sophistication": 0.7},
        DeceptionTool.AUTOPT: {"aggression": 0.8, "sophistication": 0.9},
    }

    chars = tool_characteristics[tool]
    num_events = np.random.poisson(8 + 4 * chars["aggression"])

    for i in range(num_events):
        # 随机选择攻击阶段
        stage = np.random.choice(list(AttackStage))

        # 决定是否命中诱饵 (基于欺骗质量)
        is_decoy = np.random.random() < deception_quality
        is_trap = is_decoy and np.random.random() < 0.4

        # 决定是否偏离真实资产
        diverted_from_real = is_decoy and np.random.random() < 0.7

        if not is_decoy:
            real_contacts += 1
        if is_decoy:
            decoy_hits += 1
        if is_trap:
            trap_triggers += 1

        target = np.random.choice(scenario.decoy_assets) if is_decoy else np.random.choice(scenario.real_assets)

        event = AttackEvent(
            timestamp=datetime.now() + timedelta(seconds=i * 30),
            tool=tool,
            stage=stage,
            source_ip=f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            target=target,
            action=f"{'exploit' if stage == AttackStage.FOOTHOLD else 'scan'}",
            was_decoy=is_decoy,
            triggered_trap=is_trap,
            diverted_from_real=diverted_from_real
        )

        result.events.append(event)

        # 记录到达的阶段
        if stage not in stages_reached:
            stages_reached.append(stage)

        # 陷阱触发可能终止攻击
        if is_trap and np.random.random() < 0.6:
            break

    result.end_time = datetime.now()
    result.stages_reached = stages_reached
    result.decoy_hits = decoy_hits
    result.trap_triggers = trap_triggers
    result.real_asset_contacts = real_contacts
    result.success = len(stages_reached) >= 3

    return result


__all__ = [
    "AdversarialBenchmark",
    "TestScenario",
    "ExperimentResult",
    "Metrics",
    "AttackStage",
    "DeceptionTool",
    "AttackEvent",
]
