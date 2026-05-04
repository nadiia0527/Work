from __future__ import annotations

from abc import ABC, abstractmethod

from .models import FlowFeatures, RuleOutcome, Thresholds


class PortCatalog:
    WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443})
    ADMIN_PORTS = frozenset({21, 22, 23, 3389, 5900})
    WINDOWS_SERVICE_PORTS = frozenset({135, 139, 389, 445})
    DATABASE_PORTS = frozenset({1433, 1521, 3306, 5432})

    def is_web_port(self, port: int) -> bool:
        return port in self.WEB_PORTS

    def is_admin_port(self, port: int) -> bool:
        return port in self.ADMIN_PORTS

    def is_windows_service_port(self, port: int) -> bool:
        return port in self.WINDOWS_SERVICE_PORTS

    def is_database_port(self, port: int) -> bool:
        return port in self.DATABASE_PORTS

    def is_high_dynamic_port(self, port: int) -> bool:
        return port >= 49152

    def service_group(self, port: int) -> str:
        if self.is_web_port(port):
            return "Web"
        if self.is_admin_port(port):
            return "Admin Access"
        if self.is_windows_service_port(port):
            return "Windows Service"
        if self.is_database_port(port):
            return "Database"
        if self.is_high_dynamic_port(port):
            return "Dynamic Port"
        return "Other"


class DetectionRule(ABC):
    name = ""

    def __init__(self, ports: PortCatalog) -> None:
        self._ports = ports

    @abstractmethod
    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        raise NotImplementedError

    def _add(
        self,
        score: int,
        reasons: list[str],
        condition: bool,
        points: int,
        reason: str,
    ) -> int:
        if condition:
            reasons.append(reason)
            return score + points
        return score

    def _result(self, score: int, reasons: list[str]) -> RuleOutcome:
        return RuleOutcome(name=self.name, score=score, reasons=tuple(reasons))


class WebBruteForceRule(DetectionRule):
    name = "Web Brute Force-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_web_port(features.destination_port),
            20,
            "використовується web-порт",
        )
        score = self._add(
            score,
            reasons,
            features.flow_duration <= thresholds.flow_duration_low,
            20,
            "короткий мережевий потік",
        )
        score = self._add(
            score,
            reasons,
            features.total_bytes < thresholds.total_bytes_high,
            10,
            "невеликий обсяг даних",
        )
        score = self._add(
            score,
            reasons,
            features.flow_packets_s >= thresholds.flow_packets_s_high,
            25,
            "підвищена частота пакетів",
        )
        score = self._add(
            score,
            reasons,
            features.psh > 0 and features.ack > 0,
            10,
            "активна TCP-сесія",
        )
        return self._result(score, reasons)


class WebPayloadAttackRule(DetectionRule):
    name = "Web Payload Attack-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_web_port(features.destination_port),
            20,
            "використовується web-порт",
        )
        score = self._add(
            score,
            reasons,
            features.packet_length_mean >= thresholds.packet_length_high,
            20,
            "підвищений середній розмір пакета",
        )
        score = self._add(
            score,
            reasons,
            features.fwd_bytes >= thresholds.fwd_bytes_high,
            20,
            "збільшений обсяг запиту",
        )
        score = self._add(
            score,
            reasons,
            features.bwd_bytes >= thresholds.bwd_bytes_high,
            20,
            "збільшений обсяг відповіді сервера",
        )
        score = self._add(
            score,
            reasons,
            features.flow_duration <= thresholds.flow_duration_high,
            10,
            "потік не є довготривалим фоновим з’єднанням",
        )
        score = self._add(
            score,
            reasons,
            features.psh > 0 and features.ack > 0,
            10,
            "є передача даних у TCP-сесії",
        )
        return self._result(score, reasons)


class SqlInjectionRule(DetectionRule):
    name = "SQL Injection-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_web_port(features.destination_port),
            20,
            "використовується web-порт",
        )
        score = self._add(
            score,
            reasons,
            features.fwd_bytes >= thresholds.fwd_bytes_high,
            25,
            "збільшений розмір запиту",
        )
        score = self._add(
            score,
            reasons,
            features.bwd_bytes >= thresholds.bwd_bytes_high,
            25,
            "збільшений розмір відповіді сервера",
        )
        score = self._add(
            score,
            reasons,
            features.packet_length_mean >= thresholds.packet_length_high,
            15,
            "підвищений середній розмір пакета",
        )
        score = self._add(
            score,
            reasons,
            features.bwd_bytes > features.fwd_bytes * 3,
            15,
            "відповідь сервера значно більша за запит",
        )
        return self._result(score, reasons)


class XssRule(DetectionRule):
    name = "XSS-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_web_port(features.destination_port),
            20,
            "використовується web-порт",
        )
        score = self._add(
            score,
            reasons,
            features.flow_duration <= thresholds.flow_duration_high,
            10,
            "короткий або середній web-потік",
        )
        score = self._add(
            score,
            reasons,
            features.fwd_bytes >= thresholds.fwd_bytes_high,
            25,
            "збільшений розмір запиту",
        )
        score = self._add(
            score,
            reasons,
            features.bwd_bytes < thresholds.bwd_bytes_high,
            10,
            "відповідь сервера не схожа на велику передачу даних",
        )
        score = self._add(
            score,
            reasons,
            features.packet_length_mean >= thresholds.packet_length_high,
            15,
            "підвищений середній розмір пакета",
        )
        return self._result(score, reasons)


class DosRule(DetectionRule):
    name = "DoS-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        if features.flow_packets_s >= thresholds.flow_packets_s_critical:
            score = self._add(score, reasons, True, 35, "аномально висока частота пакетів")
        elif features.flow_packets_s >= thresholds.flow_packets_s_high:
            score = self._add(score, reasons, True, 20, "підвищена частота пакетів")

        if features.flow_bytes_s >= thresholds.flow_bytes_s_critical:
            score = self._add(
                score,
                reasons,
                True,
                30,
                "аномально висока швидкість передавання даних",
            )
        elif features.flow_bytes_s >= thresholds.flow_bytes_s_high:
            score = self._add(
                score,
                reasons,
                True,
                15,
                "підвищена швидкість передавання даних",
            )

        score = self._add(
            score,
            reasons,
            features.total_packets >= thresholds.total_packets_high,
            15,
            "велика кількість пакетів",
        )
        score = self._add(
            score,
            reasons,
            features.total_bytes >= thresholds.total_bytes_high,
            15,
            "великий обсяг переданих даних",
        )
        score = self._add(
            score,
            reasons,
            features.syn > 0 and features.ack == 0,
            15,
            "SYN без ACK",
        )
        return self._result(score, reasons)


class PortScanRule(DetectionRule):
    name = "PortScan-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            features.flow_duration <= thresholds.flow_duration_low,
            25,
            "дуже короткий потік",
        )
        score = self._add(
            score,
            reasons,
            features.total_bytes < thresholds.total_bytes_high,
            10,
            "малий обсяг даних",
        )
        score = self._add(
            score,
            reasons,
            features.total_packets < thresholds.total_packets_high,
            10,
            "невелика кількість пакетів",
        )
        score = self._add(score, reasons, features.syn > 0, 20, "наявний SYN")
        score = self._add(score, reasons, features.rst > 0, 20, "наявний RST")
        score = self._add(
            score,
            reasons,
            features.ack == 0 and features.syn > 0,
            15,
            "SYN без підтвердження ACK",
        )
        score = self._add(
            score,
            reasons,
            self._ports.is_high_dynamic_port(features.destination_port),
            5,
            "звернення до високого динамічного порту",
        )
        return self._result(score, reasons)


class FtpSshBruteForceRule(DetectionRule):
    name = "FTP/SSH Brute Force-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(score, reasons, features.destination_port == 21, 25, "FTP-порт")
        score = self._add(score, reasons, features.destination_port == 22, 25, "SSH-порт")
        score = self._add(
            score,
            reasons,
            features.flow_duration <= thresholds.flow_duration_low,
            20,
            "коротка спроба з’єднання",
        )
        score = self._add(
            score,
            reasons,
            features.total_bytes < thresholds.total_bytes_high,
            15,
            "невеликий обсяг даних",
        )
        score = self._add(score, reasons, features.rst > 0, 15, "з’єднання було скинуто")
        score = self._add(
            score,
            reasons,
            features.flow_packets_s >= thresholds.flow_packets_s_high,
            20,
            "підвищена частота спроб",
        )
        return self._result(score, reasons)


class SuspiciousDataTransferRule(DetectionRule):
    name = "Suspicious Data Transfer"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        if features.total_bytes >= thresholds.total_bytes_critical:
            score = self._add(
                score,
                reasons,
                True,
                35,
                "аномально великий загальний обсяг даних",
            )
        elif features.total_bytes >= thresholds.total_bytes_high:
            score = self._add(score, reasons, True, 20, "підвищений загальний обсяг даних")

        score = self._add(
            score,
            reasons,
            features.fwd_bytes > features.bwd_bytes * 5 and features.fwd_bytes >= thresholds.fwd_bytes_high,
            25,
            "прямий трафік значно більший за зворотний",
        )
        score = self._add(
            score,
            reasons,
            features.bwd_bytes > features.fwd_bytes * 5 and features.bwd_bytes >= thresholds.bwd_bytes_high,
            25,
            "зворотний трафік значно більший за прямий",
        )
        score = self._add(
            score,
            reasons,
            features.flow_bytes_s >= thresholds.flow_bytes_s_high,
            20,
            "висока швидкість передавання даних",
        )
        score = self._add(
            score,
            reasons,
            features.flow_duration >= thresholds.flow_duration_high,
            10,
            "довготривалий потік",
        )
        return self._result(score, reasons)


class C2BeaconingRule(DetectionRule):
    name = "C2/Beaconing-like"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_high_dynamic_port(features.destination_port),
            15,
            "нестандартний високий порт",
        )
        score = self._add(
            score,
            reasons,
            features.total_bytes < thresholds.total_bytes_high,
            10,
            "невеликий обсяг даних",
        )
        score = self._add(
            score,
            reasons,
            features.total_packets < thresholds.total_packets_high,
            10,
            "невелика кількість пакетів",
        )
        score = self._add(
            score,
            reasons,
            features.idle_mean >= thresholds.idle_high,
            25,
            "довгі періоди простою",
        )
        score = self._add(
            score,
            reasons,
            features.active_mean <= thresholds.active_low,
            15,
            "коротка активна фаза",
        )
        score = self._add(
            score,
            reasons,
            features.psh > 0 and features.ack > 0,
            10,
            "періодична передача даних",
        )
        return self._result(score, reasons)


class SuspiciousServiceAccessRule(DetectionRule):
    name = "Suspicious Service Access"

    def evaluate(self, features: FlowFeatures, thresholds: Thresholds) -> RuleOutcome:
        score = 0
        reasons: list[str] = []
        score = self._add(
            score,
            reasons,
            self._ports.is_admin_port(features.destination_port),
            25,
            "звернення до адміністративного сервісу",
        )
        score = self._add(
            score,
            reasons,
            self._ports.is_windows_service_port(features.destination_port),
            20,
            "звернення до Windows-служби",
        )
        score = self._add(
            score,
            reasons,
            self._ports.is_database_port(features.destination_port),
            25,
            "звернення до сервісу бази даних",
        )
        score = self._add(
            score,
            reasons,
            features.syn > 0,
            10,
            "спроба встановлення з’єднання",
        )
        score = self._add(
            score,
            reasons,
            features.rst > 0,
            10,
            "з’єднання було скинуто",
        )
        score = self._add(
            score,
            reasons,
            features.flow_packets_s >= thresholds.flow_packets_s_high,
            15,
            "підвищена інтенсивність звернень",
        )
        return self._result(score, reasons)


def build_default_rules(ports: PortCatalog | None = None) -> tuple[DetectionRule, ...]:
    ports = ports or PortCatalog()
    return (
        WebBruteForceRule(ports),
        WebPayloadAttackRule(ports),
        SqlInjectionRule(ports),
        XssRule(ports),
        DosRule(ports),
        PortScanRule(ports),
        FtpSshBruteForceRule(ports),
        SuspiciousDataTransferRule(ports),
        C2BeaconingRule(ports),
        SuspiciousServiceAccessRule(ports),
    )
