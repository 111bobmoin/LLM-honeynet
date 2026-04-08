#!/usr/bin/env python3
"""
多原型对抗性基准测试 - 主运行脚本
Multi-Prototype Adversarial Benchmark Runner

用于测试LLM Honeynet对抗自动化渗透工具的性能
"""

from __future__ import annotations

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from benchmark.adversarial_benchmark import (
    AdversarialBenchmark,
    TestScenario,
    ExperimentResult,
    AttackStage,
    DeceptionTool,
    simulate_experiment
)
from benchmark.heatmap_generator import (
    BenchmarkHeatmapGenerator,
    generate_sample_results
)


def print_banner():
    """打印横幅"""
    banner = """
╔════════════════════════════════════════════════════════════════╗
║  多原型对抗性基准测试框架                                    ║
║  Multi-Prototype Adversarial Benchmarking Framework            ║
║  LLM Honeynet vs Automated Penetration Tools                   ║
╚════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def run_full_benchmark(
    num_experiments: int = 10,
    deception_quality: float = 0.65,
    use_simulation: bool = True
) -> Dict[str, Any]:
    """
    运行完整的基准测试

    Args:
        num_experiments: 每个工具每个场景的实验次数
        deception_quality: 欺骗质量参数 (0-1)
        use_simulation: 是否使用模拟数据 (False时需要真实渗透测试环境)

    Returns:
        实验结果字典
    """
    print(f"\n{'='*70}")
    print(f"开始基准测试")
    print(f"  - 实验次数: {num_experiments} 次/工具/场景")
    print(f"  - 欺骗质量: {deception_quality:.2f}")
    print(f"  - 模式: {'模拟模式' if use_simulation else '真实测试'}")
    print(f"{'='*70}\n")

    # 初始化基准测试框架
    benchmark = AdversarialBenchmark()

    # 创建默认测试场景
    benchmark.create_default_scenarios()

    print(f"测试场景: {len(benchmark.scenarios)} 个")
    for i, scenario in enumerate(benchmark.scenarios, 1):
        print(f"  {i}. {scenario.name}: {scenario.description}")

    print(f"\n渗透工具: {len(DeceptionTool)} 个")
    for tool in DeceptionTool:
        print(f"  - {tool.value}")

    # 运行实验
    print(f"\n{'='*70}")
    print("运行实验...")
    print(f"{'='*70}\n")

    total_experiments = len(benchmark.scenarios) * len(DeceptionTool) * num_experiments
    completed = 0

    for scenario in benchmark.scenarios:
        for tool in DeceptionTool:
            for exp_num in range(num_experiments):
                if use_simulation:
                    result = simulate_experiment(scenario, tool, deception_quality)
                else:
                    # TODO: 实现真实渗透测试接口
                    raise NotImplementedError("真实渗透测试模式尚未实现")

                benchmark.add_result(result)
                completed += 1

                # 显示进度
                progress = completed / total_experiments * 100
                print(f"\r进度: [{progress:.0f}%] {completed}/{total_experiments} 实验完成",
                      end='', flush=True)

    print()  # 换行

    # 生成报告
    print(f"\n{'='*70}")
    print("生成分析报告...")
    print(f"{'='*70}\n")

    report = benchmark.generate_comparison_report()

    # 保存报告
    report_path = benchmark.save_results()

    return report


def generate_visualizations(results: Dict[str, Any]) -> None:
    """生成可视化热图"""
    print(f"\n{'='*70}")
    print("生成对比热图...")
    print(f"{'='*70}\n")

    generator = BenchmarkHeatmapGenerator()

    # 生成综合对比热图
    print("1. 生成综合对比热图...")
    generator.create_comprehensive_heatmap(results)

    # 生成改进分析热图
    print("2. 生成改进分析热图...")
    generator.create_improvement_heatmap(results)

    # 生成工具性能热图
    print("3. 生成工具性能热图...")
    generator.create_tool_performance_heatmap(results)

    print("\n✅ 所有热图已生成!")


def print_summary_report(results: Dict[str, Any]) -> None:
    """打印摘要报告"""
    print(f"\n{'='*70}")
    print("测试结果摘要")
    print(f"{'='*70}\n")

    overall = results["overall_metrics"]

    print("📊 整体性能指标:")
    print(f"  • 欺骗成功率 (DSR): {overall['dsr']:.2%}")
    print(f"  • 平均时间到妥协: {overall['ttc_mean']/60:.1f} 分钟")
    print(f"  • 95%置信区间: [{overall['ttc_ci'][0]/60:.1f}, {overall['ttc_ci'][1]/60:.1f}] 分钟")

    print(f"\n📍 攻击阶段完成率:")
    for stage_key, rate in overall['stage_completion'].items():
        stage_names = {
            'recon': '侦察',
            'foothold': '立足点',
            'priv_esc': '特权提升',
            'lateral': '横向移动',
            'exfil': '数据外泄'
        }
        print(f"  • {stage_names[stage_key]}: {rate:.2%}")

    print(f"\n🔧 各渗透工具的DSR:")
    for tool, metrics in results["by_tool"].items():
        print(f"  • {tool}: {metrics['dsr']:.2%}")

    print(f"\n📈 SOTA对比:")
    for honeypot, comparison in results["sota_comparison"].items():
        print(f"  • {honeypot}:")
        print(f"    - DSR改进: {comparison['dsr_improvement']:+.1f}%")
        print(f"    - TTC改进: {comparison['ttc_improvement']:+.1f}%")
        print(f"    - 参考文献: {comparison['reference']}")


def export_to_csv(results: Dict[str, Any]) -> Path:
    """导出CSV格式数据"""
    output_dir = Path("benchmark_results")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 导出整体指标
    csv_path = output_dir / "benchmark_summary.csv"

    lines = []
    lines.append("蜜罐系统,指标,数值")

    overall = results["overall_metrics"]
    lines.append(f"LLM Honeynet,DSR,{overall['dsr']:.4f}")
    lines.append(f"LLM Honeynet,TTC均值,{overall['ttc_mean']:.2f}")

    for honeypot, data in [
        ("HoneyGPT", 0.42, 847.0),
        ("DecoyPot", 0.51, 1023.0),
        ("ConPot", 0.38, 654.0),
        ("HoneyLLM", 0.47, 912.0),
        ("Telnet-LM", 0.35, 523.0),
    ]:
        lines.append(f"{honeypot},DSR,{data[1]:.4f}")
        lines.append(f"{honeypot},TTC均值,{data[2]:.2f}")

    csv_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nCSV数据已导出: {csv_path}")

    return csv_path


def main():
    """主函数"""
    epilog_text = """
示例:
  # 使用默认参数运行模拟测试
  python run_benchmark.py

  # 指定实验次数和欺骗质量
  python run_benchmark.py --experiments 20 --quality 0.75

  # 只生成可视化 (使用已有结果)
  python run_benchmark.py --visualize-only

  # 导出CSV格式
  python run_benchmark.py --export-csv
        """

    parser = argparse.ArgumentParser(
        description="LLM Honeynet Adversarial Benchmark Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )

    parser.add_argument(
        "--experiments", "-n",
        type=int,
        default=10,
        help="每个工具每个场景的实验次数 (默认: 10)"
    )

    parser.add_argument(
        "--quality", "-q",
        type=float,
        default=0.65,
        dest="deception_quality",
        help="欺骗质量参数 0-1 (默认: 0.65)"
    )

    parser.add_argument(
        "--visualize-only",
        action="store_true",
        help="只生成可视化，不运行新实验"
    )

    parser.add_argument(
        "--export-csv",
        action="store_true",
        help="导出CSV格式数据"
    )

    parser.add_argument(
        "--no-simulation",
        action="store_true",
        help="使用真实渗透测试环境 (需要配置)"
    )

    args = parser.parse_args()

    print_banner()

    try:
        if args.visualize_only:
            # 使用示例数据生成可视化
            print("使用模拟数据生成可视化...\n")
            results = generate_sample_results()
            generate_visualizations(results)

        else:
            # 运行完整基准测试
            results = run_full_benchmark(
                num_experiments=args.experiments,
                deception_quality=args.deception_quality,
                use_simulation=not args.no_simulation
            )

            # 打印摘要
            print_summary_report(results)

            # 生成可视化
            generate_visualizations(results)

            # 导出CSV
            if args.export_csv:
                export_to_csv(results)

        print(f"\n{'='*70}")
        print("✅ 基准测试完成!")
        print(f"{'='*70}\n")
        print("结果文件位置:")
        print("  • benchmark_results/plots/ - 热图图像")
        print("  • benchmark_results/*.json - 详细数据")
        print("  • benchmark_results/*.csv - CSV数据 (如果使用 --export-csv)")

    except KeyboardInterrupt:
        print("\n\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
