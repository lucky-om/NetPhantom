"""
errors.py - Custom Exceptions
NetPhantom v3.3.2 — Professional Network Packet Sniffer & Analyzer
Author: Luckyverse | Cybersecurity Portfolio Project

Follows standardized error response structure:
{
    "ok": false,
    "error": {
        "code": "MACHINE_READABLE_CODE",
        "message": "Safe User Facing Message",
        "status": HTTP_STATUS_INT
    }
}
"""

import logging

# Configure structured logging
logger = logging.getLogger("NetPhantom")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class NetPhantomError(Exception):
    """
    Base Error Class for all NetPhantom application exceptions.
    """
    def __init__(self, message: str, status: int = 500, code: str = "INTERNAL_ERROR", expose: bool = False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.expose = expose
        
        # Log error immediately
        logger.error(f"[{self.code}] Status: {self.status} | Expose: {self.expose} | Detail: {message}")

    def to_dict(self) -> dict:
        """Return standardized error dictionary shape."""
        safe_msg = self.message if self.expose else "An unexpected error occurred. Please check logs."
        return {
            "ok": False,
            "error": {
                "code": self.code,
                "message": safe_msg,
                "status": self.status
            }
        }


class ValidationError(NetPhantomError):
    """HTTP 400 - Invalid input, bad BPF syntax, or malformed parameters."""
    def __init__(self, message: str):
        super().__init__(message, status=400, code="VALIDATION_ERROR", expose=True)


class PrivilegeError(NetPhantomError):
    """HTTP 403 - Missing root / Administrator socket permissions."""
    def __init__(self, message: str = "Administrator or root privileges required to capture packets."):
        super().__init__(message, status=403, code="FORBIDDEN_PRIVILEGE", expose=True)


class CaptureEngineError(NetPhantomError):
    """HTTP 500 - Internal socket or driver capture engine failure."""
    def __init__(self, message: str):
        super().__init__(message, status=500, code="CAPTURE_ENGINE_ERROR", expose=False)


class ExportError(NetPhantomError):
    """HTTP 500 - PCAP, JSON, or TXT file export failure."""
    def __init__(self, message: str):
        super().__init__(message, status=500, code="EXPORT_FAILED", expose=True)
