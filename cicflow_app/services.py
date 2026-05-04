from __future__ import annotations

from typing import BinaryIO, Iterable, Sequence

import pandas as pd

from .models import AnalysisReport, ClassificationResult, FlowFeatures, RuleOutcome, Thresholds
from .rules import DetectionRule, PortCatalog, build_default_rules

REQUIRED_COLUMNS: tuple[str, ...] = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "URG Flag Count",
    "Idle Mean",
    "Active Mean",
    "Down/Up Ratio",
)

RESULT_COLUMNS: tuple[str, ...] = (
    "Destination Port",
    "Flow Duration",
    "Total Packets",
    "Total Bytes",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Idle Mean",
    "Active Mean",
    "Down/Up Ratio",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "URG Flag Count",
    "Service Group",
    "Activity Profile",
    "Risk Level",
    "Risk Score",
    "Confidence",
    "Explanation",
)


class DatasetPreprocessor:
    def __init__(self, required_columns: Sequence[str] = REQUIRED_COLUMNS) -> None:
        self._required_columns = tuple(required_columns)
        self._allowed_columns = set(self._required_columns) | {"Label"}

    def prepare(self, source: BinaryIO) -> pd.DataFrame:
        if hasattr(source, "seek"):
            source.seek(0)

        try:
            # Читаємо лише потрібні ознаки CICFlowMeter, щоб не тримати зайві дані в пам'яті.
            frame = pd.read_csv(
                source,
                usecols=lambda name: name.strip() in self._allowed_columns,
                low_memory=False,
            )
        except ValueError as error:
            raise ValueError("CSV не схожий на експорт CICFlowMeter.") from error

        frame.columns = [name.strip() for name in frame.columns]
        loaded_columns = set(frame.columns)
        if "Label" in frame.columns:
            # Label видаляємо, бо застосунок імітує самостійний rule-based аналіз без готової відповіді.
            frame = frame.drop(columns=["Label"])

        if {"Destination Port", "Flow Duration"} - loaded_columns:
            raise ValueError("У CSV немає базових CICFlowMeter колонок для аналізу.")

        for column in self._required_columns:
            if column not in frame.columns:
                frame[column] = 0.0

        frame = frame.loc[:, self._required_columns]
        frame = frame.replace([float("inf"), float("-inf")], 0.0)

        for column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")

        return frame.fillna(0.0)


class ThresholdBuilder:
    def build(self, frame: pd.DataFrame) -> Thresholds:
        total_packets = frame["Total Fwd Packets"] + frame["Total Backward Packets"]
        total_bytes = frame["Total Length of Fwd Packets"] + frame["Total Length of Bwd Packets"]

        # Пороги рахуються від поточного CSV, тому система адаптується до конкретного набору потоків.
        return Thresholds(
            flow_duration_low=self._quantile(frame["Flow Duration"], 0.05),
            flow_duration_high=self._quantile(frame["Flow Duration"], 0.95),
            flow_packets_s_high=self._quantile(frame["Flow Packets/s"], 0.95),
            flow_packets_s_critical=self._quantile(frame["Flow Packets/s"], 0.99),
            flow_bytes_s_high=self._quantile(frame["Flow Bytes/s"], 0.95),
            flow_bytes_s_critical=self._quantile(frame["Flow Bytes/s"], 0.99),
            total_packets_high=self._quantile(total_packets, 0.95),
            total_packets_critical=self._quantile(total_packets, 0.99),
            total_bytes_high=self._quantile(total_bytes, 0.95),
            total_bytes_critical=self._quantile(total_bytes, 0.99),
            fwd_bytes_high=self._quantile(frame["Total Length of Fwd Packets"], 0.95),
            bwd_bytes_high=self._quantile(frame["Total Length of Bwd Packets"], 0.95),
            packet_length_high=self._quantile(frame["Packet Length Mean"], 0.95),
            packet_length_critical=self._quantile(frame["Packet Length Mean"], 0.99),
            idle_high=self._quantile(frame["Idle Mean"], 0.95),
            active_low=self._quantile(frame["Active Mean"], 0.05),
        )

    @staticmethod
    def _quantile(series: pd.Series, quantile: float) -> float:
        if series.empty:
            return 0.0
        return float(series.quantile(quantile))


class FlowFeatureExtractor:
    def extract(self, values: Sequence[float]) -> FlowFeatures:
        (
            destination_port,
            flow_duration,
            fwd_packets,
            bwd_packets,
            fwd_bytes,
            bwd_bytes,
            flow_bytes_s,
            flow_packets_s,
            packet_length_mean,
            syn,
            rst,
            psh,
            ack,
            fin,
            urg,
            idle_mean,
            active_mean,
            down_up_ratio,
        ) = values

        total_packets = float(fwd_packets) + float(bwd_packets)
        total_bytes = float(fwd_bytes) + float(bwd_bytes)
        return FlowFeatures(
            destination_port=int(destination_port),
            flow_duration=float(flow_duration),
            fwd_packets=float(fwd_packets),
            bwd_packets=float(bwd_packets),
            total_packets=total_packets,
            fwd_bytes=float(fwd_bytes),
            bwd_bytes=float(bwd_bytes),
            total_bytes=total_bytes,
            flow_bytes_s=float(flow_bytes_s),
            flow_packets_s=float(flow_packets_s),
            packet_length_mean=float(packet_length_mean),
            syn=float(syn),
            rst=float(rst),
            psh=float(psh),
            ack=float(ack),
            fin=float(fin),
            urg=float(urg),
            idle_mean=float(idle_mean),
            active_mean=float(active_mean),
            down_up_ratio=float(down_up_ratio),
        )


class RiskPolicy:
    def assess(self, best_outcome: RuleOutcome) -> ClassificationResult:
        if best_outcome.score < 25:
            activity_profile = "Normal-like"
            risk_level = "Low"
            confidence = "Low"
        elif best_outcome.score < 50:
            activity_profile = best_outcome.name
            risk_level = "Medium"
            confidence = "Low"
        elif best_outcome.score < 75:
            activity_profile = best_outcome.name
            risk_level = "High"
            confidence = "Medium"
        else:
            activity_profile = best_outcome.name
            risk_level = "Critical"
            confidence = "High"

        explanation = self._build_explanation(activity_profile, best_outcome.reasons)
        return ClassificationResult(
            activity_profile=activity_profile,
            risk_level=risk_level,
            confidence=confidence,
            risk_score=best_outcome.score,
            explanation=explanation,
            reasons=best_outcome.reasons,
        )

    @staticmethod
    def _build_explanation(activity_profile: str, reasons: tuple[str, ...]) -> str:
        if activity_profile == "Normal-like" or not reasons:
            return "Суттєвих тригерів підозрілої активності не виявлено."
        return "; ".join(reasons[:3]) + "."


class OutcomeCalibrator:
    WEB_PROFILES = frozenset(
        {
            "Web Brute Force-like",
            "Web Payload Attack-like",
            "SQL Injection-like",
            "XSS-like",
        }
    )

    def __init__(self, ports: PortCatalog) -> None:
        self._ports = ports

    def adjust(
        self,
        outcomes: Iterable[RuleOutcome],
        features: FlowFeatures,
        thresholds: Thresholds,
    ) -> tuple[RuleOutcome, ...]:
        return tuple(
            self._adjust_outcome(outcome, features, thresholds)
            for outcome in outcomes
        )

    def _adjust_outcome(
        self,
        outcome: RuleOutcome,
        features: FlowFeatures,
        thresholds: Thresholds,
    ) -> RuleOutcome:
        # Калібратор пом'якшує перекоси сирих евристик, щоб фінальний профіль виглядав реалістичніше.
        score = outcome.score
        score += self._bonus(outcome.name, features, thresholds)
        score -= self._penalty(outcome.name, features, thresholds)
        return RuleOutcome(
            name=outcome.name,
            score=max(0, min(100, int(score))),
            reasons=outcome.reasons,
        )

    def _bonus(self, profile: str, features: FlowFeatures, thresholds: Thresholds) -> int:
        flood_signal = self._is_flood_signal(features, thresholds)
        scan_signal = self._is_scan_signal(features)
        bulk_signal = self._is_bulk_signal(features, thresholds)

        if profile == "DoS-like":
            bonus = 0
            if flood_signal:
                bonus += 25
            if features.flow_bytes_s >= thresholds.flow_bytes_s_high and features.flow_packets_s >= thresholds.flow_packets_s_high:
                bonus += 15
            if features.total_packets >= thresholds.total_packets_critical:
                bonus += 15
            if features.syn > 0 and features.ack == 0:
                bonus += 10
            return bonus

        if profile == "PortScan-like":
            bonus = 0
            if scan_signal:
                bonus += 25
            if features.total_packets <= max(6.0, thresholds.total_packets_high * 0.10):
                bonus += 10
            if self._ports.is_high_dynamic_port(features.destination_port):
                bonus += 5
            return bonus

        if profile == "Suspicious Data Transfer" and bulk_signal:
            return 15

        if profile == "C2/Beaconing-like":
            core_indicators = self._beacon_core_indicators(features, thresholds)
            return 10 if core_indicators >= 3 else 0

        return 0

    def _penalty(self, profile: str, features: FlowFeatures, thresholds: Thresholds) -> int:
        flood_signal = self._is_flood_signal(features, thresholds)
        scan_signal = self._is_scan_signal(features)
        bulk_signal = self._is_bulk_signal(features, thresholds)
        is_web = self._ports.is_web_port(features.destination_port)
        is_special_service = (
            self._ports.is_admin_port(features.destination_port)
            or self._ports.is_windows_service_port(features.destination_port)
            or self._ports.is_database_port(features.destination_port)
        )

        if profile in self.WEB_PROFILES:
            penalty = 0 if is_web else 45
            if flood_signal:
                penalty += 30
            penalty += self._web_profile_penalty(profile, features, thresholds)
            return penalty

        if profile == "FTP/SSH Brute Force-like":
            penalty = 0 if features.destination_port in {21, 22} else 40
            if flood_signal:
                penalty += 10
            return penalty

        if profile == "Suspicious Service Access":
            return 0 if is_special_service else 35

        if profile == "Suspicious Data Transfer":
            penalty = 0
            if not bulk_signal and features.total_bytes < thresholds.total_bytes_high:
                penalty += 25
            return penalty

        if profile == "C2/Beaconing-like":
            penalty = 0
            if self._beacon_core_indicators(features, thresholds) < 3:
                penalty += 35
            if scan_signal:
                penalty += 20
            if flood_signal or features.total_packets >= thresholds.total_packets_high:
                penalty += 25
            return penalty

        if profile == "PortScan-like":
            penalty = 0
            if not scan_signal:
                penalty += 10
            if bulk_signal:
                penalty += 15
            return penalty

        return 0

    @staticmethod
    def _is_flood_signal(features: FlowFeatures, thresholds: Thresholds) -> bool:
        return (
            features.flow_packets_s >= thresholds.flow_packets_s_high
            and features.total_packets >= thresholds.total_packets_high
        ) or (
            features.flow_packets_s >= thresholds.flow_packets_s_critical
            or features.total_packets >= thresholds.total_packets_critical
        )

    @staticmethod
    def _is_scan_signal(features: FlowFeatures) -> bool:
        return (features.syn > 0 or features.rst > 0) and features.ack == 0

    @staticmethod
    def _is_bulk_signal(features: FlowFeatures, thresholds: Thresholds) -> bool:
        return (
            features.total_bytes >= thresholds.total_bytes_high
            and features.flow_bytes_s >= thresholds.flow_bytes_s_high
        )

    def _beacon_core_indicators(self, features: FlowFeatures, thresholds: Thresholds) -> int:
        checks = (
            self._ports.is_high_dynamic_port(features.destination_port),
            features.idle_mean >= thresholds.idle_high,
            features.active_mean <= thresholds.active_low,
            features.total_bytes < thresholds.total_bytes_high,
        )
        return sum(checks)

    def _web_profile_penalty(
        self,
        profile: str,
        features: FlowFeatures,
        thresholds: Thresholds,
    ) -> int:
        if profile == "XSS-like":
            indicators = self._count_true(
                features.fwd_bytes >= thresholds.fwd_bytes_high,
                features.packet_length_mean >= thresholds.packet_length_high,
            )
            return 25 if indicators == 0 else 0

        if profile == "SQL Injection-like":
            indicators = self._count_true(
                features.fwd_bytes >= thresholds.fwd_bytes_high,
                features.bwd_bytes >= thresholds.bwd_bytes_high,
                features.bwd_bytes > features.fwd_bytes * 3,
                features.packet_length_mean >= thresholds.packet_length_high,
            )
            return 35 if indicators < 2 else 0

        if profile == "Web Payload Attack-like":
            indicators = self._count_true(
                features.packet_length_mean >= thresholds.packet_length_high,
                features.fwd_bytes >= thresholds.fwd_bytes_high,
                features.bwd_bytes >= thresholds.bwd_bytes_high,
                features.psh > 0 and features.ack > 0,
            )
            return 25 if indicators < 2 else 0

        if profile == "Web Brute Force-like":
            indicators = self._count_true(
                features.flow_duration <= thresholds.flow_duration_low,
                features.flow_packets_s >= thresholds.flow_packets_s_high,
                features.total_bytes < thresholds.total_bytes_high,
            )
            return 15 if indicators < 2 else 0

        return 0

    @staticmethod
    def _count_true(*checks: bool) -> int:
        return sum(checks)


class FlowAnalyzer:
    def __init__(
        self,
        preprocessor: DatasetPreprocessor,
        threshold_builder: ThresholdBuilder,
        extractor: FlowFeatureExtractor,
        rules: Iterable[DetectionRule],
        calibrator: OutcomeCalibrator,
        risk_policy: RiskPolicy,
        ports: PortCatalog,
    ) -> None:
        self._preprocessor = preprocessor
        self._threshold_builder = threshold_builder
        self._extractor = extractor
        self._rules = tuple(rules)
        self._calibrator = calibrator
        self._risk_policy = risk_policy
        self._ports = ports

    def analyze(self, source: BinaryIO) -> AnalysisReport:
        frame = self._preprocessor.prepare(source)
        thresholds = self._threshold_builder.build(frame)

        rows: list[dict[str, object]] = []
        # Основний конвеєр аналізу: очищення -> пороги -> ознаки -> класифікація -> рядок звіту.
        for values in frame.itertuples(index=False, name=None):
            features = self._extractor.extract(values)
            result = self._classify(features, thresholds)
            rows.append(self._to_result_row(features, result))

        results = pd.DataFrame(rows, columns=RESULT_COLUMNS)
        return AnalysisReport(results=results, thresholds=thresholds)

    def _classify(self, features: FlowFeatures, thresholds: Thresholds) -> ClassificationResult:
        outcomes = self._calibrator.adjust(
            (rule.evaluate(features, thresholds) for rule in self._rules),
            features,
            thresholds,
        )
        best_outcome = max(
            outcomes,
            key=lambda outcome: outcome.score,
        )
        return self._risk_policy.assess(best_outcome)

    def _to_result_row(
        self,
        features: FlowFeatures,
        result: ClassificationResult,
    ) -> dict[str, object]:
        return {
            "Destination Port": features.destination_port,
            "Flow Duration": features.flow_duration,
            "Total Packets": features.total_packets,
            "Total Bytes": features.total_bytes,
            "Flow Bytes/s": features.flow_bytes_s,
            "Flow Packets/s": features.flow_packets_s,
            "Packet Length Mean": features.packet_length_mean,
            "Idle Mean": features.idle_mean,
            "Active Mean": features.active_mean,
            "Down/Up Ratio": features.down_up_ratio,
            "SYN Flag Count": features.syn,
            "RST Flag Count": features.rst,
            "PSH Flag Count": features.psh,
            "ACK Flag Count": features.ack,
            "FIN Flag Count": features.fin,
            "URG Flag Count": features.urg,
            "Service Group": self._ports.service_group(features.destination_port),
            "Activity Profile": result.activity_profile,
            "Risk Level": result.risk_level,
            "Risk Score": result.risk_score,
            "Confidence": result.confidence,
            "Explanation": result.explanation,
        }


def build_default_analyzer() -> FlowAnalyzer:
    ports = PortCatalog()
    return FlowAnalyzer(
        preprocessor=DatasetPreprocessor(),
        threshold_builder=ThresholdBuilder(),
        extractor=FlowFeatureExtractor(),
        rules=build_default_rules(ports),
        calibrator=OutcomeCalibrator(ports),
        risk_policy=RiskPolicy(),
        ports=ports,
    )
