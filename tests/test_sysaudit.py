import io
import sys
from contextlib import redirect_stdout

import pytest

import sysaudit


def test_render_text_handles_permission_findings(capsys):
    report = {
        "timestamp": "2026-07-17T00:00:00Z",
        "unsafe_files": [
            {"file": "/tmp/example.txt", "permissions": "0o777", "owner": "root"}
        ],
        "top_processes": [],
        "disk_warnings": [],
        "audit_passed": False,
    }

    sysaudit.render_text(report)
    captured = capsys.readouterr()
    assert "SECURITY" in captured.out
    assert "/tmp/example.txt" in captured.out
