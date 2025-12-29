"""
PII Firewall Edge - Python SDK

Enterprise-grade PII detection with zero AI and zero data retention.
Detects 152 PII types across 50+ countries in 5ms.

Version: 2.4.0
API Reference: https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

__version__ = "2.4.0"

BASE_URL = "https://pii-firewall-edge.p.rapidapi.com"
API_HOST = "pii-firewall-edge.p.rapidapi.com"


@dataclass
class RedactionResult:
    """Result of a PII redaction operation."""
    redacted: str
    detections: int
    warning: Optional[str] = None
    
    @property
    def has_pii(self) -> bool:
        """Check if any PII was detected."""
        return self.detections > 0


class PIIFirewallError(Exception):
    """Exception raised when PII Firewall API call fails."""
    
    def __init__(self, message: str, status_code: int = 0, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable
    
    def __str__(self):
        if self.status_code:
            return f"[{self.status_code}] {self.args[0]}"
        return self.args[0]


class PIIFirewallClient:
    """
    PII Firewall Edge API client.
    
    Args:
        api_key: Your RapidAPI key from https://rapidapi.com
        timeout: Request timeout in seconds (default: 10)
    
    Example:
        >>> client = PIIFirewallClient("YOUR_API_KEY")
        >>> result = client.redact_fast("Contact john@test.com at 555-1234")
        >>> print(result.redacted)
        Contact [EMAIL] at [PHONE_US]
    """
    
    def __init__(self, api_key: str, timeout: int = 10):
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key is required")
        self.api_key = api_key
        self.timeout = timeout
    
    def redact_fast(self, text: str) -> RedactionResult:
        """
        Redact PII using fast mode (2-5ms latency).
        
        Detects: emails, phones, SSN, credit cards, API keys, IBANs, etc.
        Does NOT detect: human names, addresses.
        
        Args:
            text: The text to scan for PII
            
        Returns:
            RedactionResult with redacted text and detection count
            
        Raises:
            PIIFirewallError: If API call fails
        """
        return self._redact(text, "/v1/redact/fast", "label")
    
    def redact_fast_masked(self, text: str) -> RedactionResult:
        """
        Redact PII using fast mode with masking (asterisks).
        
        Args:
            text: The text to scan for PII
            
        Returns:
            RedactionResult with PII replaced by asterisks
        """
        return self._redact(text, "/v1/redact/fast", "mask")
    
    def redact_deep(self, text: str) -> RedactionResult:
        """
        Redact PII using deep mode (5-15ms latency).
        
        Detects everything in fast mode + human names + addresses.
        Uses 2000+ name gazetteer for detection without AI.
        
        Args:
            text: The text to scan for PII
            
        Returns:
            RedactionResult with redacted text and detection count
        """
        return self._redact(text, "/v1/redact/deep", "label")
    
    def redact_deep_masked(self, text: str) -> RedactionResult:
        """
        Redact PII using deep mode with masking (asterisks).
        
        Args:
            text: The text to scan for PII
            
        Returns:
            RedactionResult with PII replaced by asterisks
        """
        return self._redact(text, "/v1/redact/deep", "mask")
    
    def _redact(self, text: str, endpoint: str, mode: str) -> RedactionResult:
        """Internal method to make API request."""
        # Input validation
        if text is None:
            raise PIIFirewallError("Text cannot be None", 400)
        if not isinstance(text, str):
            raise PIIFirewallError("Text must be a string", 400)
        if not text.strip():
            raise PIIFirewallError("Text cannot be empty", 400)
        
        url = f"{BASE_URL}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": API_HOST,
        }
        body = json.dumps({"text": text, "mode": mode}).encode("utf-8")
        
        try:
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
                return RedactionResult(
                    redacted=data.get("redacted", ""),
                    detections=data.get("detections", 0),
                    warning=data.get("warning")
                )
        except urllib.error.HTTPError as e:
            try:
                error_body = json.loads(e.read().decode("utf-8"))
                error_message = error_body.get("error", "Unknown error")
            except:
                error_message = str(e.reason)
            raise self._map_http_error(e.code, error_message)
        except urllib.error.URLError as e:
            raise PIIFirewallError(f"Network error: {str(e.reason)}", 0, retryable=True)
        except TimeoutError:
            raise PIIFirewallError("Request timeout", 0, retryable=True)
    
    def _map_http_error(self, status_code: int, message: str) -> PIIFirewallError:
        """Map HTTP status code to descriptive error."""
        error_map = {
            400: ("Bad Request", False),
            401: ("Unauthorized: Invalid or missing API key", False),
            403: ("Forbidden: API key does not have access", False),
            413: ("Payload Too Large", False),
            429: ("Rate Limit Exceeded: Upgrade your plan or wait", True),
            500: ("Server Error: Please try again later", True),
        }
        
        if status_code in error_map:
            base_msg, retryable = error_map[status_code]
            return PIIFirewallError(f"{base_msg}: {message}", status_code, retryable)
        
        return PIIFirewallError(f"HTTP Error {status_code}: {message}", status_code)


# Convenience function
def create_client(api_key: str, timeout: int = 10) -> PIIFirewallClient:
    """
    Create a PII Firewall client.
    
    Args:
        api_key: Your RapidAPI key
        timeout: Request timeout in seconds (default: 10)
        
    Returns:
        Configured PIIFirewallClient instance
    """
    return PIIFirewallClient(api_key, timeout)
