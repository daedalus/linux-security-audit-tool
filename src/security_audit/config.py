"""Configuration management for the Linux Security Audit Tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


@dataclass
class AuditConfig:
    checks: dict[str, Any] = field(default_factory=dict)

    critical_files: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        "/etc/shadow": {
            "perms": "0600",
            "accept_perms": ["-rw-------", "-rw-r-----"],
        },
        "/etc/gshadow": {
            "perms": "0600",
            "accept_perms": ["-rw-------", "-rw-r-----"],
        },
        "/etc/sudoers": {
            "perms": "0440",
            "accept_perms": ["-r--r-----", "-rw-r-----"],
        },
        "/etc/passwd": {
            "perms": "0644",
            "accept_perms": ["-rw-r--r--", "-rw-rw-r--"],
        },
        "/etc/group": {
            "perms": "0644",
            "accept_perms": ["-rw-r--r--", "-rw-rw-r--"],
        },
    })

    expected_ports: set[int] = field(default_factory=lambda: {22, 80, 443, 8443})
    sensitive_ports: set[int] = field(default_factory=lambda: {
        23, 514, 3306, 5432, 6379, 27017, 9200,
    })

    dangerous_modules: list[str] = field(default_factory=lambda: [
        "dccp", "sctp", "rds", "tipc", "usb-storage", "floppy",
    ])

    preload_paths: list[str] = field(default_factory=lambda: [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d/",
    ])

    pass_max_days_threshold: int = 90
    pass_min_days_threshold: int = 1
    pass_warn_age_threshold: int = 7

    _loaded_path: Path | None = None

    @classmethod
    def load(cls, path: str | Path | None = None) -> AuditConfig:
        cfg = cls()
        if path is None:
            return cfg
        path = Path(path)
        if not path.exists():
            return cfg
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return cfg
        cfg._loaded_path = path
        cfg._apply_yaml(raw)
        return cfg

    def _apply_yaml(self, raw: dict) -> None:
        checks = raw.get("checks", raw)
        if "critical_files" in checks:
            overrides = checks["critical_files"]
            for path, values in overrides.items():
                if path in self.critical_files:
                    self.critical_files[path].update(values)
                else:
                    self.critical_files[path] = dict(values)

        if "expected_ports" in checks:
            self.expected_ports = set(checks["expected_ports"])
        if "sensitive_ports" in checks:
            self.sensitive_ports = set(checks["sensitive_ports"])
        if "dangerous_modules" in checks:
            self.dangerous_modules = list(checks["dangerous_modules"])
        if "preload_paths" in checks:
            self.preload_paths = list(checks["preload_paths"])
        if "pass_max_days_threshold" in checks:
            self.pass_max_days_threshold = int(checks["pass_max_days_threshold"])
        if "pass_min_days_threshold" in checks:
            self.pass_min_days_threshold = int(checks["pass_min_days_threshold"])
        if "pass_warn_age_threshold" in checks:
            self.pass_warn_age_threshold = int(checks["pass_warn_age_threshold"])


config: AuditConfig = AuditConfig()


def load_config(path: str | Path | None = None) -> AuditConfig:
    global config
    config = AuditConfig.load(path)
    return config
