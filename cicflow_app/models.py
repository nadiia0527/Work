from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True, slots=True)
class Thresholds:
    flow_duration_low: float
    flow_duration_high: float
    flow_packets_s_high: float
    flow_packets_s_critical: float
    flow_bytes_s_high: float
    flow_bytes_s_critical: float
    total_packets_high: float
    total_packets_critical: float
    total_bytes_high: float
    total_bytes_critical: float
    fwd_bytes_high: float
    bwd_bytes_high: float
    packet_length_high: float
    packet_length_critical: float
    idle_high: float
    active_low: float


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    destination_port: int
    flow_duration: float
    fwd_packets: float
    bwd_packets: float
    total_packets: float
    fwd_bytes: float
    bwd_bytes: float
    total_bytes: float
    flow_bytes_s: float
    flow_packets_s: float
    packet_length_mean: float
    syn: float
    rst: float
    psh: float
    ack: float
    fin: float
    urg: float
    idle_mean: float
    active_mean: float
    down_up_ratio: float


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    name: str
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    activity_profile: str
    risk_level: str
    confidence: str
    risk_score: int
    explanation: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    results: pd.DataFrame
    thresholds: Thresholds
