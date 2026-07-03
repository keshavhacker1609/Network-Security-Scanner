"""Tests for configuration loading and modular risk-database merging."""

import textwrap

import pytest

from config import Config


def _write(path, text):
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def test_default_config_loads():
    cfg = Config()  # ships with the repo
    assert cfg.risk_database  # non-empty
    assert 3306 in cfg.risk_database
    assert cfg.output.get("default_formats")


def test_modular_merge_and_override(tmp_path):
    _write(tmp_path / "base_db.yaml", """
        risk_database:
          80:
            service: HTTP
            level: MEDIUM
            cvss_score: 5.0
    """)
    _write(tmp_path / "custom_db.yaml", """
        risk_database:
          80:
            service: HTTP
            level: HIGH        # overrides base
            cvss_score: 7.5
          8000:
            service: DevServer
            level: MEDIUM
            cvss_score: 5.0
    """)
    _write(tmp_path / "config.yaml", """
        scanner: {timeout: 300}
        logging: {level: INFO, file: logs/x.log}
        output: {reports_dir: reports}
        risk_database_files:
          - base_db.yaml
          - custom_db.yaml
        risk_database: {}
    """)
    cfg = Config(str(tmp_path / "config.yaml"))
    assert cfg.risk_database[80]["level"] == "HIGH"  # later file wins
    assert cfg.risk_database[8000]["service"] == "DevServer"


def test_inline_has_final_say(tmp_path):
    _write(tmp_path / "db.yaml", """
        risk_database:
          22: {service: SSH, level: MEDIUM, cvss_score: 5.3}
    """)
    _write(tmp_path / "config.yaml", """
        scanner: {timeout: 300}
        logging: {level: INFO, file: logs/x.log}
        output: {reports_dir: reports}
        risk_database_files: [db.yaml]
        risk_database:
          22: {service: SSH, level: HIGH, cvss_score: 9.0}
    """)
    cfg = Config(str(tmp_path / "config.yaml"))
    assert cfg.risk_database[22]["level"] == "HIGH"


def test_missing_referenced_file_raises(tmp_path):
    _write(tmp_path / "config.yaml", """
        scanner: {timeout: 300}
        logging: {level: INFO, file: logs/x.log}
        output: {reports_dir: reports}
        risk_database_files: [does_not_exist.yaml]
    """)
    with pytest.raises(FileNotFoundError):
        Config(str(tmp_path / "config.yaml"))


def test_empty_risk_database_raises(tmp_path):
    _write(tmp_path / "config.yaml", """
        scanner: {timeout: 300}
        logging: {level: INFO, file: logs/x.log}
        output: {reports_dir: reports}
        risk_database: {}
    """)
    with pytest.raises(ValueError):
        Config(str(tmp_path / "config.yaml"))


def test_missing_required_section_raises(tmp_path):
    _write(tmp_path / "config.yaml", """
        logging: {level: INFO}
        output: {reports_dir: reports}
        risk_database:
          22: {service: SSH, level: MEDIUM, cvss_score: 5.3}
    """)
    with pytest.raises(ValueError):
        Config(str(tmp_path / "config.yaml"))
