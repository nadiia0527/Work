from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .models import AnalysisReport
from .localization import (
    CONFIDENCE_ORDER,
    NORMAL_PROFILE,
    RISK_ORDER,
    localize_results,
    localize_thresholds,
)
from .rules import PortCatalog

SCORE_BAND_ORDER: tuple[str, ...] = ("0-24", "25-49", "50-74", "75-100")


@dataclass(frozen=True, slots=True)
class DashboardMetric:
    label: str
    value: str
    detail: str
    tone: str


@dataclass(frozen=True, slots=True)
class DashboardViewModel:
    results: pd.DataFrame
    metrics: tuple[DashboardMetric, ...]
    thresholds_frame: pd.DataFrame
    posture_label: str
    insights: tuple[str, ...]


class DashboardBuilder:
    def __init__(self, ports: PortCatalog | None = None) -> None:
        self._ports = ports or PortCatalog()

    def build(self, report: AnalysisReport) -> DashboardViewModel:
        # ViewModel відокремлює підготовку даних для UI від аналітичного ядра застосунку.
        results = report.results.copy()
        if "Service Group" not in results.columns:
            results["Service Group"] = results["Destination Port"].map(self._ports.service_group)

        results["Score Band"] = pd.cut(
            results["Risk Score"].clip(lower=0, upper=100),
            bins=[-0.1, 24.9, 49.9, 74.9, 100.0],
            labels=SCORE_BAND_ORDER,
        ).astype(str)

        results = localize_results(results)
        thresholds_frame = localize_thresholds(report.thresholds)
        posture_label = self._build_posture_label(results)
        return DashboardViewModel(
            results=results,
            metrics=self._build_metrics(results, report.thresholds.flow_packets_s_high),
            thresholds_frame=thresholds_frame,
            posture_label=posture_label,
            insights=self._build_insights(results, posture_label),
        )

    @staticmethod
    def apply_filters(
        results: pd.DataFrame,
        risk_levels: tuple[str, ...],
        profiles: tuple[str, ...],
        service_groups: tuple[str, ...],
        suspicious_only: bool,
    ) -> pd.DataFrame:
        frame = results.loc[
            results["Рівень ризику"].isin(risk_levels)
            & results["Профіль активності"].isin(profiles)
            & results["Група сервісу"].isin(service_groups)
        ]
        if suspicious_only:
            frame = frame.loc[frame["Профіль активності"] != NORMAL_PROFILE]
        return frame.reset_index(drop=True)

    def _build_metrics(
        self,
        results: pd.DataFrame,
        flow_packets_s_high: float,
    ) -> tuple[DashboardMetric, ...]:
        total_flows = len(results)
        suspicious_share = self._share(results["Профіль активності"] != NORMAL_PROFILE)
        elevated_share = self._share(results["Рівень ризику"].isin({"Високий", "Критичний"}))
        critical_share = self._share(results["Рівень ризику"] == "Критичний")
        dominant_profile, dominant_share = self._top_profile(results)
        primary_service, service_share = self._top_share(results["Група сервісу"])
        burst_share = self._share(results["Пакетів/с"] >= flow_packets_s_high)

        return (
            DashboardMetric("Потоки", f"{total_flows:,}", "завантажений датасет", "neutral"),
            DashboardMetric("Підозрілі", f"{suspicious_share:.1f}%", "частка підозрілих потоків", "warm"),
            DashboardMetric("Високий + Критичний", f"{elevated_share:.1f}%", f"критичний: {critical_share:.1f}%", "danger"),
            DashboardMetric("Домінуючий профіль", dominant_profile, f"{dominant_share:.1f}% від підозрілих", "accent"),
            DashboardMetric("Основний сервіс", primary_service, f"{service_share:.1f}% потоків", "calm"),
            DashboardMetric("Інтенсивні", f"{burst_share:.1f}%", "вище порогу пакетів/с", "accent"),
        )

    def _build_posture_label(self, results: pd.DataFrame) -> str:
        critical_share = self._share(results["Рівень ризику"] == "Критичний")
        elevated_share = self._share(results["Рівень ризику"].isin({"Високий", "Критичний"}))
        if critical_share >= 12.0:
            return "Критична експозиція"
        if elevated_share >= 35.0:
            return "Підвищений рівень загроз"
        if elevated_share >= 15.0:
            return "Зафіксовані аномалії"
        return "Переважно нормальний трафік"

    def _build_insights(self, results: pd.DataFrame, posture_label: str) -> tuple[str, ...]:
        profile, profile_share = self._top_profile(results)
        service, service_share = self._top_share(results["Група сервісу"])
        port = int(results["Порт призначення"].mode().iat[0]) if not results.empty else 0
        median_duration_seconds = float(results["Тривалість потоку"].median()) / 1_000_000 if not results.empty else 0.0

        return (
            f"{posture_label}: основний тиск зосереджений у профілі `{profile}` ({profile_share:.1f}%).",
            f"Головна поверхня атаки - трафік групи `{service}` ({service_share:.1f}%), найчастіше з портом `{port}`.",
            f"Медіанна тривалість потоку становить `{median_duration_seconds:.2f}` с, що допомагає відокремити короткі сплески від довгих сесій.",
        )

    @staticmethod
    def _share(mask: pd.Series) -> float:
        if mask.empty:
            return 0.0
        return float(mask.mean() * 100)

    @staticmethod
    def _top_share(series: pd.Series) -> tuple[str, float]:
        if series.empty:
            return "н/д", 0.0
        counts = series.value_counts(normalize=True)
        return str(counts.index[0]), float(counts.iloc[0] * 100)

    @staticmethod
    def _top_profile(results: pd.DataFrame) -> tuple[str, float]:
        suspicious = results.loc[results["Профіль активності"] != NORMAL_PROFILE, "Профіль активності"]
        if suspicious.empty:
            return NORMAL_PROFILE, 0.0
        counts = suspicious.value_counts(normalize=True)
        return str(counts.index[0]), float(counts.iloc[0] * 100)
