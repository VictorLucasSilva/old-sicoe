# core/utils/xml.py
"""
Parser XML blindado contra XXE/External Entity.
Tenta usar defusedxml; se não disponível, ajusta XMLParser do stdlib
desabilitando DTD e entidades externas.
"""
from typing import Any
try:
    from defusedxml.ElementTree import fromstring as _fromstring  # type: ignore
    DEFUSED_AVAILABLE = True
except Exception:
    DEFUSED_AVAILABLE = False
    import xml.etree.ElementTree as ET

class XXEError(Exception):
    pass

def parse_xml_safe(xml_bytes: bytes) -> Any:
    if not xml_bytes:
        raise XXEError("empty xml")
    if DEFUSED_AVAILABLE:
        try:
            return _fromstring(xml_bytes)
        except Exception as e:
            raise XXEError(str(e))
    else:
        try:
            parser = ET.XMLParser()
            return ET.fromstring(xml_bytes, parser=parser)
        except Exception as e:
            raise XXEError(str(e))
