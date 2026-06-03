from __future__ import annotations

import io
import requests
import altair as alt
import pandas as pd
import streamlit as st

from cicflow_app import build_default_analyzer
from cicflow_app.dashboard import (
    CONFIDENCE_ORDER,
    RISK_ORDER,
    SCORE_BAND_ORDER,
    DashboardBuilder,
    DashboardMetric,
    DashboardViewModel,
)
from cicflow_app.localization import NORMAL_PROFILE

RISK_COLORS = {
    "Низький": "#5B8E7D",
    "Середній": "#D9A441",
    "Високий": "#E06C3A",
    "Критичний": "#C44536",
}


CSV_URL = "https://raw.githubusercontent.com/nadiia0527/Work/main/data.csv.gz"


@st.cache_data(show_spinner=False)
def analyze_bytes(file_bytes: bytes) -> DashboardViewModel:
    analyzer = build_default_analyzer()
    report = analyzer.analyze(io.BytesIO(file_bytes))
    return DashboardBuilder().build(report)


class StreamlitFlowApp:
    def __init__(self) -> None:
        self._builder = DashboardBuilder()

    def run(self) -> None:
        st.set_page_config(
            page_title="Аналізатор ризику CICFlowMeter",
            layout="wide",
        )

        self._apply_theme()

        st.sidebar.title("Завантаження")
        mode = st.sidebar.radio("Джерело даних", ["GitHub (авто)", "Завантажити файл"])

        file_bytes = None
        file_name = "github_data.csv.gz"

        # =========================
        # 1. ЗАВАНТАЖЕННЯ ДАНИХ
        # =========================
        if mode == "GitHub (авто)":
            response = requests.get(CSV_URL)

            if response.status_code != 200:
                st.error("Не вдалося завантажити CSV з GitHub")
                return

            file_bytes = response.content

        else:
            uploaded_file = st.file_uploader("CSV / CSV.GZ", type=["csv", "gz"])

            if uploaded_file is None:
                st.info("Завантаж файл або обери GitHub режим")
                return

            file_bytes = uploaded_file.getvalue()
            file_name = uploaded_file.name

        if not file_bytes:
            st.error("Файл порожній")
            return

        # =========================
        # 2. АНАЛІЗ
        # =========================
        try:
            with st.spinner("Аналіз даних..."):
                dashboard = analyze_bytes(file_bytes)

        except Exception as e:
            st.error(f"Помилка аналізу: {e}")
            return

        # =========================
        # 3. ФІЛЬТРИ
        # =========================
        filters = self._render_sidebar_filters(dashboard)

        filtered = self._builder.apply_filters(
            dashboard.results,
            risk_levels=filters["risk_levels"],
            profiles=filters["profiles"],
            service_groups=filters["service_groups"],
            suspicious_only=filters["suspicious_only"],
        )

        # =========================
        # 4. UI
        # =========================
        self._render_hero(
            file_name,
            len(file_bytes),
            dashboard,
            len(filtered),
        )

        self._render_metric_grid(dashboard.metrics)

        if filtered.empty:
            st.warning("Немає даних для вибраних фільтрів")
            return

        tab1, tab2, tab3, tab4 = st.tabs(
            ["Огляд", "Геометрія", "Потоки", "Пороги"]
        )

        with tab1:
            self._render_overview_tab(filtered, dashboard.insights)

        with tab2:
            self._render_geometry_tab(filtered)

        with tab3:
            self._render_flows_tab(filtered, filters["row_limit"])

        with tab4:
            self._render_thresholds_tab(dashboard)

    # =========================
    # THEME
    # =========================
    def _apply_theme(self) -> None:
        st.markdown(
            """
            <style>
            .stApp { background: #f6f1e8; }
            </style>
            """,
            unsafe_allow_html=True,
        )

    # =========================
    # SIDEBAR
    # =========================
    def _render_sidebar_filters(self, dashboard: DashboardViewModel) -> dict:
        with st.sidebar:
            st.subheader("Фільтри")

            suspicious_only = st.checkbox("Лише підозрілі")

            risk_levels = st.multiselect(
                "Рівень ризику",
                list(RISK_ORDER),
                default=list(RISK_ORDER),
            )

            profiles = st.multiselect(
                "Профілі",
                dashboard.results["Профіль активності"].unique().tolist(),
            )

            service_groups = st.multiselect(
                "Сервіси",
                dashboard.results["Група сервісу"].unique().tolist(),
            )

            row_limit = st.slider("Рядки", 25, 500, 150)

        return {
            "suspicious_only": suspicious_only,
            "risk_levels": tuple(risk_levels),
            "profiles": tuple(profiles),
            "service_groups": tuple(service_groups),
            "row_limit": row_limit,
        }

    # =========================
    # PLACEHOLDER UI (скорочено)
    # =========================
    def _render_hero(self, *args, **kwargs):
        st.title("CICFlowMeter Dashboard")

    def _render_metric_grid(self, metrics):
        st.write(metrics)

    def _render_overview_tab(self, results, insights):
        st.dataframe(results)

    def _render_geometry_tab(self, results):
        st.dataframe(results)

    def _render_flows_tab(self, results, limit):
        st.dataframe(results.head(limit))

    def _render_thresholds_tab(self, dashboard):
        st.dataframe(dashboard.thresholds_frame)


if __name__ == "__main__":
    StreamlitFlowApp().run()
