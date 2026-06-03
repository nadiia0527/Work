from __future__ import annotations

import io

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
PROFILE_PALETTE = [
    "#0F766E",
    "#D97706",
    "#2563EB",
    "#B45309",
    "#9333EA",
    "#DC2626",
    "#059669",
    "#7C3AED",
    "#0891B2",
    "#BE123C",
]
SERVICE_PALETTE = [
    "#0F766E",
    "#F59E0B",
    "#E76F51",
    "#3A86FF",
    "#7C3AED",
    "#94A3B8",
]


@st.cache_data(show_spinner=False)
def analyze_bytes(file_bytes: bytes) -> DashboardViewModel:
    # Кешування особливо корисне для великих CSV: фільтри не запускають повний аналіз повторно.
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
            initial_sidebar_state="expanded",
        )
        self._apply_theme()

        uploaded_file = self._render_sidebar_uploader()
        if uploaded_file is None:
            self._render_empty_state()
            return

        file_bytes = uploaded_file.getvalue()
        if not file_bytes:
            st.error("Файл порожній.")
            return

        try:
            with st.spinner("Формую профіль потоків і карту загроз..."):
                dashboard = analyze_bytes(file_bytes)
        except ValueError as error:
            st.error(str(error))
            return

        filters = self._render_sidebar_filters(dashboard)
        filtered = self._builder.apply_filters(
            dashboard.results,
            risk_levels=filters["risk_levels"],
            profiles=filters["profiles"],
            service_groups=filters["service_groups"],
            suspicious_only=filters["suspicious_only"],
        )

        self._render_hero(uploaded_file.name, len(file_bytes), dashboard, len(filtered))
        self._render_metric_grid(dashboard.metrics)

        if filtered.empty:
            st.warning("Поточні фільтри не залишили потоків для візуалізації.")
            self._render_export_section(dashboard.results, filtered, uploaded_file.name)
            return

        # Дашборд розділено на сценарії перегляду, щоб у звіті було простіше показати різні ракурси аналізу.
        overview_tab, geometry_tab, flows_tab, thresholds_tab = st.tabs(
            ["Огляд сигналів", "Геометрія трафіку", "Потоки", "Пороги"]
        )

        with overview_tab:
            self._render_overview_tab(filtered, dashboard.insights)
        with geometry_tab:
            self._render_geometry_tab(filtered)
        with flows_tab:
            self._render_flows_tab(filtered, filters["row_limit"])
            self._render_export_section(dashboard.results, filtered, uploaded_file.name)
        with thresholds_tab:
            self._render_thresholds_tab(dashboard)

    def _apply_theme(self) -> None:
        # Візуальний стиль ізольовано від бізнес-логіки, тому інтерфейс можна змінювати незалежно.
        st.markdown(
            """
            <style>
            @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Space+Grotesk:wght@500;700&display=swap');

            :root {
                --bg: #f6f1e8;
                --panel: rgba(255, 255, 255, 0.78);
                --panel-strong: rgba(255, 255, 255, 0.94);
                --ink: #16243a;
                --muted: #5e6a7d;
                --line: rgba(22, 36, 58, 0.08);
                --accent: #0f766e;
                --warm: #d97706;
                --danger: #c44536;
                --calm: #2563eb;
            }

            .stApp {
                background:
                    radial-gradient(circle at top left, rgba(248, 206, 176, 0.65), transparent 32%),
                    radial-gradient(circle at top right, rgba(181, 227, 216, 0.75), transparent 30%),
                    linear-gradient(180deg, #f7f2ea 0%, #eef3f7 100%);
                color: var(--ink);
                font-family: 'IBM Plex Sans', sans-serif;
            }

            h1, h2, h3, h4, [data-testid="stMarkdownContainer"] h1, [data-testid="stMarkdownContainer"] h2 {
                font-family: 'Space Grotesk', sans-serif;
                letter-spacing: -0.03em;
                color: var(--ink);
            }

            p, li, label, [data-testid="stCaptionContainer"] {
                font-family: 'IBM Plex Sans', sans-serif;
            }

            [data-testid="stSidebar"] {
                background: rgba(255, 255, 255, 0.74);
                border-right: 1px solid var(--line);
            }

            [data-testid="stVerticalBlockBorderWrapper"] {
                background: var(--panel);
                border: 1px solid var(--line);
                border-radius: 24px;
                box-shadow: 0 18px 45px rgba(22, 36, 58, 0.07);
            }

            .hero-card {
                background: linear-gradient(135deg, rgba(15,118,110,0.96), rgba(24,64,102,0.92));
                border-radius: 30px;
                padding: 1.75rem 1.75rem 1.55rem;
                color: #f8fbff;
                box-shadow: 0 22px 55px rgba(17, 48, 77, 0.22);
            }

            .hero-eyebrow {
                text-transform: uppercase;
                letter-spacing: 0.18em;
                font-size: 0.74rem;
                opacity: 0.76;
                margin-bottom: 0.8rem;
            }

            .hero-title {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 2.45rem;
                line-height: 1;
                margin: 0;
            }

            .hero-copy {
                margin: 0.95rem 0 1.15rem;
                font-size: 1rem;
                max-width: 60rem;
                opacity: 0.92;
            }

            .hero-pills {
                display: flex;
                flex-wrap: wrap;
                gap: 0.65rem;
            }

            .hero-pill {
                display: inline-flex;
                align-items: center;
                padding: 0.46rem 0.8rem;
                border-radius: 999px;
                background: rgba(255, 255, 255, 0.14);
                border: 1px solid rgba(255, 255, 255, 0.18);
                font-size: 0.9rem;
            }

            .metric-card {
                background: var(--panel-strong);
                border-radius: 24px;
                padding: 1rem 1.05rem;
                min-height: 138px;
                border: 1px solid var(--line);
                box-shadow: 0 12px 32px rgba(22, 36, 58, 0.06);
            }

            .metric-label {
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.12em;
                color: var(--muted);
                margin-bottom: 0.72rem;
            }

            .metric-value {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 1.7rem;
                line-height: 1.05;
                color: var(--ink);
                margin-bottom: 0.5rem;
            }

            .metric-detail {
                font-size: 0.92rem;
                color: var(--muted);
            }

            .metric-card.tone-accent { border-top: 4px solid var(--accent); }
            .metric-card.tone-warm { border-top: 4px solid var(--warm); }
            .metric-card.tone-danger { border-top: 4px solid var(--danger); }
            .metric-card.tone-calm { border-top: 4px solid var(--calm); }
            .metric-card.tone-neutral { border-top: 4px solid rgba(22, 36, 58, 0.18); }

            .insight-card {
                background: linear-gradient(180deg, rgba(255,255,255,0.96), rgba(248,251,255,0.86));
                border-radius: 24px;
                border: 1px solid var(--line);
                padding: 1rem 1.05rem;
                min-height: 138px;
            }

            .insight-label {
                text-transform: uppercase;
                letter-spacing: 0.12em;
                font-size: 0.72rem;
                color: var(--muted);
                margin-bottom: 0.7rem;
            }

            .insight-copy {
                color: var(--ink);
                font-size: 0.98rem;
                line-height: 1.55;
            }

            .empty-card {
                background: rgba(255,255,255,0.86);
                border-radius: 28px;
                border: 1px solid var(--line);
                padding: 2.2rem 2rem;
                box-shadow: 0 18px 45px rgba(22, 36, 58, 0.08);
            }

            .section-note {
                color: var(--muted);
                font-size: 0.92rem;
            }

            .stTabs [data-baseweb="tab-list"] {
                gap: 0.6rem;
            }

            .stTabs [data-baseweb="tab"] {
                height: 48px;
                border-radius: 999px;
                background: rgba(255,255,255,0.6);
                border: 1px solid var(--line);
                padding: 0 1rem;
                color: var(--ink);
            }

            .stTabs [aria-selected="true"] {
                background: rgba(15, 118, 110, 0.12);
                border-color: rgba(15, 118, 110, 0.28);
            }

            .stDownloadButton button, .stButton button {
                border-radius: 999px;
                border: 1px solid rgba(15,118,110,0.25);
                background: linear-gradient(135deg, rgba(15,118,110,0.94), rgba(37,99,235,0.9));
                color: white;
                font-weight: 600;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

    def _render_sidebar_uploader(self):
        with st.sidebar:
            st.markdown("### Завантаження")
            uploaded_file = st.file_uploader("CSV-файл CICFlowMeter", type=["csv"])
            st.caption(
                "Евристичний аналіз мережевих потоків для експортів CICFlowMeter. "
                "Фільтри нижче змінюють поточний зріз дашборда та експорт CSV."
            )
            return uploaded_file

    def _render_sidebar_filters(self, dashboard: DashboardViewModel) -> dict[str, object]:
        with st.sidebar:
            st.markdown("### Керування виглядом")
            suspicious_only = st.toggle("Лише підозрілі потоки", value=False)
            risk_levels = st.multiselect(
                "Рівні ризику",
                options=list(RISK_ORDER),
                default=list(RISK_ORDER),
            )
            profiles = st.multiselect(
                "Профілі активності",
                options=sorted(dashboard.results["Профіль активності"].unique().tolist()),
                default=sorted(dashboard.results["Профіль активності"].unique().tolist()),
            )
            service_groups = st.multiselect(
                "Групи сервісів",
                options=sorted(dashboard.results["Група сервісу"].unique().tolist()),
                default=sorted(dashboard.results["Група сервісу"].unique().tolist()),
            )
            row_limit = st.slider("Рядків у таблиці", min_value=25, max_value=500, value=150, step=25)
            st.markdown("### Пояснення")
            st.caption(
                "Потоки рівня `Критичний` і `Високий` варто перевіряти першими. "
                "Позначки web-, scan- та DoS-активності залишаються евристичними, бо модель бачить лише статистику потоків."
            )

        return {
            "suspicious_only": suspicious_only,
            "risk_levels": tuple(risk_levels or RISK_ORDER),
            "profiles": tuple(profiles or dashboard.results["Профіль активності"].unique().tolist()),
            "service_groups": tuple(service_groups or dashboard.results["Група сервісу"].unique().tolist()),
            "row_limit": row_limit,
        }

    def _render_empty_state(self) -> None:
        st.markdown(
            """
            <div class="empty-card">
                <div class="hero-eyebrow" style="color:#5e6a7d;">Мережева аналітика</div>
                <h1 style="margin:0;">Аналізатор ризику CICFlowMeter</h1>
                <p class="hero-copy" style="color:#5e6a7d; max-width:48rem;">
                    Завантажте CSV-файл із потоками мережевого трафіку. Застосунок очистить дані,
                    автоматично побудує пороги, згенерує профіль ризику і покаже дашборд для курсової:
                    KPI, розподіли, таблицю потоків, пороги та експорт результату.
                </p>
                <p class="section-note" style="margin:0;">
                    Порада: для найкращої візуалізації використовуйте експорти CICFlowMeter формату CIC-IDS2017.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    def _render_hero(
        self,
        file_name: str,
        file_size_bytes: int,
        dashboard: DashboardViewModel,
        visible_rows: int,
    ) -> None:
        st.markdown(
            f"""
            <div class="hero-card">
                <div class="hero-eyebrow">Поверхня сигналів</div>
                <h1 class="hero-title">Аналізатор ризику CICFlowMeter</h1>
                <p class="hero-copy">
                    Компактний OOP-дашборд для аналізу потоків: застосунок очищує датасет, калібрує
                    профілі схожої на атаку активності, ранжує ризик і дає візуально сильний звітний вигляд для курсової роботи.
                </p>
                <div class="hero-pills">
                    <span class="hero-pill">Файл: {file_name}</span>
                    <span class="hero-pill">Розмір: {file_size_bytes / (1024 * 1024):.2f} MB</span>
                    <span class="hero-pill">Видимі потоки: {visible_rows:,} / {len(dashboard.results):,}</span>
                    <span class="hero-pill">{dashboard.posture_label}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")

    def _render_metric_grid(self, metrics: tuple[DashboardMetric, ...]) -> None:
        for offset in range(0, len(metrics), 3):
            columns = st.columns(3)
            for column, metric in zip(columns, metrics[offset : offset + 3]):
                column.markdown(
                    f"""
                    <div class="metric-card tone-{metric.tone}">
                        <div class="metric-label">{metric.label}</div>
                        <div class="metric-value">{metric.value}</div>
                        <div class="metric-detail">{metric.detail}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            st.write("")

    def _render_overview_tab(self, results: pd.DataFrame, insights: tuple[str, ...]) -> None:
        first, second = st.columns(2)
        with first:
            with st.container(border=True):
                st.subheader("Розподіл за рівнем ризику")
                st.altair_chart(self._risk_chart(results), use_container_width=True)
        with second:
            with st.container(border=True):
                st.subheader("Домінуючі профілі активності")
                st.altair_chart(self._profile_chart(results), use_container_width=True)

        third, fourth = st.columns((1.15, 0.85))
        with third:
            with st.container(border=True):
                st.subheader("Розподіл score")
                st.altair_chart(self._score_band_chart(results), use_container_width=True)
        with fourth:
            with st.container(border=True):
                st.subheader("Рівні впевненості")
                st.altair_chart(self._confidence_chart(results), use_container_width=True)

        insight_columns = st.columns(3)
        for column, insight in zip(insight_columns, insights):
            column.markdown(
                f"""
                <div class="insight-card">
                    <div class="insight-label">Спостереження</div>
                    <div class="insight-copy">{insight}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    def _render_geometry_tab(self, results: pd.DataFrame) -> None:
        first, second = st.columns((1.05, 0.95))
        with first:
            with st.container(border=True):
                st.subheader("Найчастіші цільові порти")
                st.altair_chart(self._top_ports_chart(results), use_container_width=True)
        with second:
            with st.container(border=True):
                st.subheader("Структура сервісних груп")
                st.altair_chart(self._service_chart(results), use_container_width=True)

        with st.container(border=True):
            st.subheader("Геометрія трафіку")
            st.caption("Scatter вибірково семплюється для читабельності та використовує логарифмічні осі для пакетів і байтів.")
            st.altair_chart(self._scatter_chart(results), use_container_width=True)

    def _render_flows_tab(self, results: pd.DataFrame, row_limit: int) -> None:
        ordered = results.sort_values(
            by=["Оцінка ризику", "Пакетів/с", "Усього байтів"],
            ascending=[False, False, False],
        )
        st.subheader("Таблиця потоків")
        st.caption(f"Показано перші {min(row_limit, len(ordered)):,} рядків із поточного зрізу.")
        st.dataframe(ordered.head(row_limit), use_container_width=True, hide_index=True)

    def _render_thresholds_tab(self, dashboard: DashboardViewModel) -> None:
        first, second = st.columns((0.95, 1.05))
        with first:
            with st.container(border=True):
                st.subheader("Автоматично розраховані пороги")
                st.dataframe(
                    dashboard.thresholds_frame.assign(
                        Значення=dashboard.thresholds_frame["Значення"].map(lambda value: f"{value:,.3f}")
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
        with second:
            with st.container(border=True):
                st.subheader("Нотатки до інтерпретації")
                st.markdown(
                    """
                    - Пороги обчислюються безпосередньо з завантаженого файлу, тому підлаштовуються під конкретний CSV.
                    - Значення `Q95` і `Q99` допомагають відокремити короткі, інтенсивні або надмірні потоки від локальної базової лінії.
                    - Позначки web-, scan-, DoS- та beaconing-активності залишаються евристичними, бо в датасеті немає вмісту пакетів.
                    - Для курсового проєкту це формує сильну візуальну історію: очищення, побудова порогів, scoring та експорт.
                    """
                )

    def _render_export_section(
        self,
        full_results: pd.DataFrame,
        filtered_results: pd.DataFrame,
        original_name: str,
    ) -> None:
        st.subheader("Експорт")
        first, second = st.columns(2)
        first.download_button(
            "Експортувати повний аналіз",
            data=full_results.to_csv(index=False).encode("utf-8"),
            file_name=original_name.rsplit(".", 1)[0] + "_analiz_povnyi.csv",
            mime="text/csv",
            use_container_width=True,
        )
        second.download_button(
            "Експортувати поточний зріз",
            data=filtered_results.to_csv(index=False).encode("utf-8"),
            file_name=original_name.rsplit(".", 1)[0] + "_potocnyi_zriz.csv",
            mime="text/csv",
            use_container_width=True,
        )

    def _risk_chart(self, results: pd.DataFrame) -> alt.Chart:
        data = self._value_count_frame(results["Рівень ризику"], "Рівень ризику", RISK_ORDER)
        return self._bar_chart(
            data,
            x="Рівень ризику:N",
            y="Потоки:Q",
            color_field="Рівень ризику",
            color_range=[RISK_COLORS[level] for level in RISK_ORDER],
            sort=list(RISK_ORDER),
        )

    def _profile_chart(self, results: pd.DataFrame) -> alt.Chart:
        profiles = results.loc[results["Профіль активності"] != NORMAL_PROFILE, "Профіль активності"]
        if profiles.empty:
            profiles = results["Профіль активності"]
        data = (
            profiles.value_counts()
            .head(8)
            .rename_axis("Профіль активності")
            .reset_index(name="Потоки")
        )
        return self._horizontal_bar_chart(
            data,
            category="Профіль активності",
            value="Потоки",
            palette=PROFILE_PALETTE[: len(data)],
        )

    def _score_band_chart(self, results: pd.DataFrame) -> alt.Chart:
        data = self._value_count_frame(results["Діапазон оцінки"], "Діапазон оцінки", SCORE_BAND_ORDER)
        return self._bar_chart(
            data,
            x="Діапазон оцінки:N",
            y="Потоки:Q",
            color_field="Діапазон оцінки",
            color_range=["#94A3B8", "#D9A441", "#E06C3A", "#C44536"],
            sort=list(SCORE_BAND_ORDER),
        )

    def _confidence_chart(self, results: pd.DataFrame) -> alt.Chart:
        data = self._value_count_frame(results["Впевненість"], "Впевненість", CONFIDENCE_ORDER)
        return self._bar_chart(
            data,
            x="Впевненість:N",
            y="Потоки:Q",
            color_field="Впевненість",
            color_range=["#94A3B8", "#D9A441", "#0F766E"],
            sort=list(CONFIDENCE_ORDER),
        )

    def _top_ports_chart(self, results: pd.DataFrame) -> alt.Chart:
        data = (
            results.groupby(["Порт призначення", "Група сервісу"], as_index=False)
            .size()
            .rename(columns={"size": "Потоки"})
            .sort_values("Потоки", ascending=False)
            .head(10)
        )
        data["Порт"] = data["Порт призначення"].astype(str)
        chart = alt.Chart(data).mark_bar(cornerRadiusEnd=8).encode(
            x=alt.X("Потоки:Q", title="Потоки"),
            y=alt.Y("Порт:N", sort="-x", title="Порт призначення"),
            color=alt.Color(
                "Група сервісу:N",
                scale=alt.Scale(range=SERVICE_PALETTE),
                legend=alt.Legend(title="Група сервісу"),
            ),
            tooltip=["Порт:N", "Група сервісу:N", "Потоки:Q"],
        )
        return self._style_chart(chart)

    def _service_chart(self, results: pd.DataFrame) -> alt.Chart:
        data = (
            results["Група сервісу"]
            .value_counts()
            .rename_axis("Група сервісу")
            .reset_index(name="Потоки")
        )
        chart = alt.Chart(data).mark_arc(innerRadius=60, outerRadius=110).encode(
            theta=alt.Theta("Потоки:Q"),
            color=alt.Color(
                "Група сервісу:N",
                scale=alt.Scale(range=SERVICE_PALETTE[: len(data)]),
                legend=alt.Legend(title="Група сервісу"),
            ),
            tooltip=["Група сервісу:N", "Потоки:Q"],
        )
        return self._style_chart(chart)

    def _scatter_chart(self, results: pd.DataFrame) -> alt.Chart:
        sample = results.sample(min(3500, len(results)), random_state=42).copy()
        # Для читабельності scatter будується на підвибірці, але зберігає загальну форму розподілу.
        sample["Пакети для графіка"] = sample["Усього пакетів"].clip(lower=1.0)
        sample["Байти для графіка"] = sample["Усього байтів"].clip(lower=1.0)
        chart = alt.Chart(sample).mark_circle(size=62, opacity=0.58).encode(
            x=alt.X("Пакети для графіка:Q", scale=alt.Scale(type="log"), title="Усього пакетів"),
            y=alt.Y("Байти для графіка:Q", scale=alt.Scale(type="log"), title="Усього байтів"),
            color=alt.Color(
                "Рівень ризику:N",
                scale=alt.Scale(
                    domain=list(RISK_ORDER),
                    range=[RISK_COLORS[level] for level in RISK_ORDER],
                ),
                legend=alt.Legend(title="Рівень ризику"),
            ),
            tooltip=[
                "Порт призначення:N",
                "Група сервісу:N",
                "Профіль активності:N",
                "Рівень ризику:N",
                "Оцінка ризику:Q",
                "Пакетів/с:Q",
                "Байтів/с:Q",
            ],
        )
        return self._style_chart(chart).interactive()

    def _bar_chart(
        self,
        data: pd.DataFrame,
        x: str,
        y: str,
        color_field: str,
        color_range: list[str],
        sort: list[str],
    ) -> alt.Chart:
        chart = alt.Chart(data).mark_bar(cornerRadiusTopLeft=8, cornerRadiusTopRight=8).encode(
            x=alt.X(x, sort=sort, title=None),
            y=alt.Y(y, title="Потоки"),
            color=alt.Color(
                f"{color_field}:N",
                scale=alt.Scale(domain=sort, range=color_range),
                legend=None,
            ),
            tooltip=[f"{color_field}:N", "Потоки:Q"],
        )
        return self._style_chart(chart)

    def _horizontal_bar_chart(
        self,
        data: pd.DataFrame,
        category: str,
        value: str,
        palette: list[str],
    ) -> alt.Chart:
        chart = alt.Chart(data).mark_bar(cornerRadiusEnd=8).encode(
            x=alt.X(f"{value}:Q", title="Потоки"),
            y=alt.Y(f"{category}:N", sort="-x", title=None),
            color=alt.Color(
                f"{category}:N",
                scale=alt.Scale(domain=data[category].tolist(), range=palette),
                legend=None,
            ),
            tooltip=[f"{category}:N", f"{value}:Q"],
        )
        return self._style_chart(chart)

    def _style_chart(self, chart: alt.Chart) -> alt.Chart:
        return (
            chart.properties(height=320)
            .configure_view(stroke=None)
            .configure_axis(
                labelColor="#16243A",
                titleColor="#5E6A7D",
                labelFont="IBM Plex Sans",
                titleFont="IBM Plex Sans",
                gridColor="rgba(22,36,58,0.08)",
            )
            .configure_legend(
                labelFont="IBM Plex Sans",
                titleFont="IBM Plex Sans",
                labelColor="#16243A",
                titleColor="#5E6A7D",
            )
        )

    @staticmethod
    def _value_count_frame(
        series: pd.Series,
        name: str,
        order: tuple[str, ...],
    ) -> pd.DataFrame:
        counts = series.value_counts().reindex(order, fill_value=0)
        return counts.rename_axis(name).reset_index(name="Потоки")


if __name__ == "__main__":
    StreamlitFlowApp().run()
