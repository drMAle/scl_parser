"""Source-level SCL/XML checks, distinct from IEC 61850 semantic rules."""
from __future__ import annotations
import xml.etree.ElementTree as ET

def validate_xml(filename):
    try:
        ET.parse(filename)
        return []
    except ET.ParseError as exc:
        return [('ERROR','XML-001','XML',f'Invalid XML/SCL document: {exc}')]
