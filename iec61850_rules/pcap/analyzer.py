"""Combined PCAP analysis for IEC 61850 GOOSE and MMS/Reports."""
from __future__ import annotations
from .goose import read_goose
from .reports import analyze_reports


def analyze_pcap(path):
    """Return a neutral result dictionary suitable for GUI integration."""
    goose = list(read_goose(path))
    reports = analyze_reports(path)
    return {
        'file': str(path),
        'goose': goose,
        'reports': reports,
        'summary': {
            'goose_frames': len(goose),
            'mms_observations': len(reports),
        }
    }
