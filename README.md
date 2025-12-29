# PII Firewall Edge - Python SDK

Enterprise-grade PII detection for Python applications. Zero AI. Zero Logs. 5ms latency.

## Installation

```bash
# Copy the file to your project
cp pii_firewall.py your_project/

# Or install via pip (coming soon)
# pip install pii-firewall-edge
```

**Note**: No external dependencies required! Uses Python's built-in `urllib`.

## Quick Start

### 1. Get Your API Key

Sign up at [RapidAPI](https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge) to get your free API key (500 requests/month).

### 2. Basic Usage

```python
from pii_firewall import PIIFirewallClient

client = PIIFirewallClient("YOUR_RAPIDAPI_KEY")

# Fast mode (emails, phones, SSNs, credit cards, etc.)
result = client.redact_fast(
    "Contact john@company.com at 555-123-4567. SSN: 123-45-6789"
)

print(result.redacted)
# Output: Contact [EMAIL] at [PHONE_US]. SSN: [SSN]

print(result.detections)
# Output: 3

print(result.has_pii)
# Output: True
```


## Integration with OpenAI

Sanitize user input before sending to ChatGPT:

```python
import os
from openai import OpenAI
from pii_firewall import PIIFirewallClient

pii_client = PIIFirewallClient(os.environ["RAPIDAPI_KEY"])
openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def safe_chat(user_message: str) -> str:
    # Step 1: Redact PII before sending to LLM
    result = pii_client.redact_fast(user_message)
    
    # Step 2: Send sanitized text to OpenAI
    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": result.redacted}]
    )
    
    return response.choices[0].message.content
```

## Error Handling

```python
from pii_firewall import PIIFirewallClient, PIIFirewallError

client = PIIFirewallClient("YOUR_KEY")

try:
    result = client.redact_fast(user_input)
    print(result.redacted)
except PIIFirewallError as e:
    print(f"Error {e.status_code}: {e}")
    
    if e.status_code == 401:
        print("Check your API key")
    elif e.status_code == 413:
        print("Text too large - max 20KB (Basic) or 100KB (Pro+)")
    elif e.status_code == 429:
        print("Rate limit exceeded - upgrade or wait")
    elif e.retryable:
        print("Temporary error - retry in a few seconds")
```

## Pricing

| Plan | Price | Requests/Month |
|------|-------|----------------|
| Basic | $0 | 500 |
| Pro | $5 | 5,000 |
| Ultra | $10 | 20,000 |
| Mega | $25 | 75,000 |

## PII Types Detected

152 types across 50+ countries including:

- **Contact**: Email, Phone (US/UK/IN/Intl)
- **Government**: SSN, Passport, Driver's License, Tax IDs
- **Financial**: Credit Card, IBAN, SWIFT, Crypto addresses
- **Healthcare**: NPI, DEA, Medicare, MRN
- **Developer**: AWS, GitHub, Stripe, OpenAI, Slack API keys

## Support

- **Documentation**: [RapidAPI Docs](https://rapidapi.com/image-zero-trust-security-labs/api/pii-firewall-edge)
- **SDK Examples**: [GitHub](https://github.com/myProjectsRavi/pii-firewall-edge-api-examples)
- **Email**: [Contact Support](mailto:piifirewalledge@gmail.com)

## License

MIT License
