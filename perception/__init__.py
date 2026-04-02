"""Perception package for honeynet log analysis and attack stage recognition."""

from .analyzer import analyze_host, discover_hosts, HostAnalysis, HostEvent
from .rules import load_rules, Rules
from .openai_summary import OpenAISummarizer
from .rag_store import ShadowRAGStore

__all__ = [
    "analyze_host",
    "discover_hosts",
    "load_rules",
    "Rules",
    "HostAnalysis",
    "HostEvent",
    "OpenAISummarizer",
    "ShadowRAGStore",
]
