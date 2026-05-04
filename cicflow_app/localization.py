from __future__ import annotations

from dataclasses import asdict

import pandas as pd

from .models import Thresholds

# Локалізація винесена окремо, щоб доменна логіка не залежала від мови інтерфейсу.
PROFILE_LABELS = {
    "Normal-like": "Нормальний трафік",
    "Web Brute Force-like": "Схоже на Web Brute Force",
    "Web Payload Attack-like": "Схоже на Web Payload Attack",
    "SQL Injection-like": "Схоже на SQL Injection",
    "XSS-like": "Схоже на XSS",
    "DoS-like": "Схоже на DoS",
    "PortScan-like": "Схоже на PortScan",
    "FTP/SSH Brute Force-like": "Схоже на FTP/SSH Brute Force",
    "Suspicious Data Transfer": "Підозріла передача даних",
    "C2/Beaconing-like": "Схоже на C2/Beaconing",
    "Suspicious Service Access": "Підозрілий доступ до сервісу",
}

RISK_LABELS = {
    "Low": "Низький",
    "Medium": "Середній",
    "High": "Високий",
    "Critical": "Критичний",
}

CONFIDENCE_LABELS = {
    "Low": "Низька",
    "Medium": "Середня",
    "High": "Висока",
}

SERVICE_GROUP_LABELS = {
    "Web": "Веб",
    "Admin Access": "Адміністративний доступ",
    "Windows Service": "Windows-служба",
    "Database": "База даних",
    "Dynamic Port": "Динамічний порт",
    "Other": "Інше",
}

COLUMN_LABELS = {
    "Destination Port": "Порт призначення",
    "Flow Duration": "Тривалість потоку",
    "Total Packets": "Усього пакетів",
    "Total Bytes": "Усього байтів",
    "Flow Bytes/s": "Байтів/с",
    "Flow Packets/s": "Пакетів/с",
    "Packet Length Mean": "Середня довжина пакета",
    "Idle Mean": "Середній простій",
    "Active Mean": "Середня активність",
    "Down/Up Ratio": "Співвідношення Down/Up",
    "SYN Flag Count": "Кількість SYN",
    "RST Flag Count": "Кількість RST",
    "PSH Flag Count": "Кількість PSH",
    "ACK Flag Count": "Кількість ACK",
    "FIN Flag Count": "Кількість FIN",
    "URG Flag Count": "Кількість URG",
    "Service Group": "Група сервісу",
    "Activity Profile": "Профіль активності",
    "Risk Level": "Рівень ризику",
    "Risk Score": "Оцінка ризику",
    "Confidence": "Впевненість",
    "Explanation": "Пояснення",
    "Score Band": "Діапазон оцінки",
}

THRESHOLD_LABELS = {
    "flow_duration_low": "Коротка тривалість потоку (Q05)",
    "flow_duration_high": "Довга тривалість потоку (Q95)",
    "flow_packets_s_high": "Високий рівень пакетів/с (Q95)",
    "flow_packets_s_critical": "Критичний рівень пакетів/с (Q99)",
    "flow_bytes_s_high": "Висока швидкість байтів/с (Q95)",
    "flow_bytes_s_critical": "Критична швидкість байтів/с (Q99)",
    "total_packets_high": "Велика кількість пакетів (Q95)",
    "total_packets_critical": "Критична кількість пакетів (Q99)",
    "total_bytes_high": "Великий обсяг байтів (Q95)",
    "total_bytes_critical": "Критичний обсяг байтів (Q99)",
    "fwd_bytes_high": "Високий прямий трафік (Q95)",
    "bwd_bytes_high": "Високий зворотний трафік (Q95)",
    "packet_length_high": "Велика середня довжина пакета (Q95)",
    "packet_length_critical": "Критична середня довжина пакета (Q99)",
    "idle_high": "Тривалий простій (Q95)",
    "active_low": "Коротка активна фаза (Q05)",
}

RISK_ORDER: tuple[str, ...] = tuple(RISK_LABELS[level] for level in ("Low", "Medium", "High", "Critical"))
CONFIDENCE_ORDER: tuple[str, ...] = tuple(
    CONFIDENCE_LABELS[level] for level in ("Low", "Medium", "High")
)
NORMAL_PROFILE = PROFILE_LABELS["Normal-like"]


def localize_results(frame: pd.DataFrame) -> pd.DataFrame:
    localized = frame.copy()
    # Сирі англомовні значення перетворюємо на зрозумілий звітний вигляд для дашборда та експорту.
    localized["Activity Profile"] = localized["Activity Profile"].map(PROFILE_LABELS).fillna(localized["Activity Profile"])
    localized["Risk Level"] = localized["Risk Level"].map(RISK_LABELS).fillna(localized["Risk Level"])
    localized["Confidence"] = localized["Confidence"].map(CONFIDENCE_LABELS).fillna(localized["Confidence"])
    localized["Service Group"] = localized["Service Group"].map(SERVICE_GROUP_LABELS).fillna(localized["Service Group"])
    return localized.rename(columns=COLUMN_LABELS)


def localize_thresholds(thresholds: Thresholds) -> pd.DataFrame:
    payload = asdict(thresholds)
    return pd.DataFrame(
        {
            "Поріг": [THRESHOLD_LABELS.get(name, name) for name in payload],
            "Значення": list(payload.values()),
        }
    )
