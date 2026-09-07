"""
UPI Intent String Parser
Parses UPI deep link URLs and analyzes them for suspicious patterns.
Format: upi://pay?pa=address@upi&pn=Name&am=1000&cu=INR&tn=Note
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional


# Known suspicious UPI handle patterns
SUSPICIOUS_HANDLE_PATTERNS = [
    r'\.(?:lucky|prize|winner|lottery|reward|cash|free|gift)@',
    r'(?:refund|claim|urgent|verify|update|kyc)\d*@',
    r'^[a-z]{1,3}\d{8,}@',  # Very short name + long number
]

# Known legitimate UPI suffixes
LEGITIMATE_SUFFIXES = [
    '@okicici', '@okhdfcbank', '@okaxis', '@oksbi',
    '@ybl', '@paytm', '@upi', '@apl', '@ibl',
    '@axl', '@sbi', '@icici', '@hdfc',
]

# Suspicious transaction note patterns  
SUSPICIOUS_NOTE_PATTERNS = [
    r'\b(refund|prize|lottery|winner|won|reward|cashback)\b',
    r'\b(urgent|immediately|hurry|fast|quick)\b',
    r'\b(verify|verification|kyc|update)\b',
    r'\b(fine|penalty|fee|charge)\b',
    r'\b(blocked|suspended|deactivated)\b',
]


def parse_upi_intent(upi_string: str) -> Dict:
    """Parse a UPI intent string and analyze it."""
    upi_string = upi_string.strip()
    
    result = {
        "valid": False,
        "parsed": {},
        "warnings": [],
        "risk_score": 0,
        "raw": upi_string,
    }
    
    # Try to parse as URL
    if not upi_string.lower().startswith("upi://"):
        # Try to extract UPI ID directly
        upi_match = re.search(r'[\w.-]+@[\w]+', upi_string)
        if upi_match:
            result["parsed"]["pa"] = upi_match.group()
            result["valid"] = True
            result["warnings"].append({
                "en": "Extracted UPI ID from text (not a standard UPI intent URL)",
                "hi": "टेक्स्ट से UPI ID निकाला गया (मानक UPI इंटेंट URL नहीं)"
            })
        else:
            result["warnings"].append({
                "en": "Invalid UPI intent format. Expected: upi://pay?pa=address@upi",
                "hi": "अमान्य UPI इंटेंट प्रारूप। अपेक्षित: upi://pay?pa=address@upi"
            })
            return result
    else:
        try:
            parsed = urlparse(upi_string)
            params = parse_qs(parsed.query)
            
            field_map = {
                'pa': 'Payee Address',
                'pn': 'Payee Name',
                'am': 'Amount',
                'cu': 'Currency',
                'tn': 'Transaction Note',
                'tr': 'Transaction Reference',
                'mc': 'Merchant Code',
                'mode': 'Payment Mode',
            }
            
            for key in field_map:
                if key in params:
                    result["parsed"][key] = params[key][0]
            
            result["valid"] = 'pa' in result["parsed"]
            
            if not result["valid"]:
                result["warnings"].append({
                    "en": "No payee address (pa) found in UPI intent",
                    "hi": "UPI इंटेंट में कोई प्राप्तकर्ता पता (pa) नहीं मिला"
                })
                return result
                
        except Exception as e:
            result["warnings"].append({
                "en": f"Failed to parse UPI intent: {str(e)}",
                "hi": f"UPI इंटेंट पार्स करने में विफल: {str(e)}"
            })
            return result
    
    # Analyze the parsed UPI intent for risks
    risk_score = 0
    pa = result["parsed"].get("pa", "")
    tn = result["parsed"].get("tn", "")
    amount = result["parsed"].get("am", "")
    
    # Check payee address
    for pattern in SUSPICIOUS_HANDLE_PATTERNS:
        if re.search(pattern, pa, re.IGNORECASE):
            risk_score += 30
            result["warnings"].append({
                "en": f"Suspicious UPI handle pattern detected: {pa}",
                "hi": f"संदिग्ध UPI हैंडल पैटर्न पाया गया: {pa}"
            })
            break
    
    # Check transaction note
    if tn:
        for pattern in SUSPICIOUS_NOTE_PATTERNS:
            if re.search(pattern, tn, re.IGNORECASE):
                risk_score += 20
                result["warnings"].append({
                    "en": f"Suspicious keyword in transaction note: '{tn}'",
                    "hi": f"लेन-देन नोट में संदिग्ध शब्द: '{tn}'"
                })
                break
    
    # Check amount (high amounts are suspicious in scam context)
    if amount:
        try:
            amt = float(amount)
            if amt > 10000:
                risk_score += 15
                result["warnings"].append({
                    "en": f"High transaction amount: ₹{amt:,.2f}",
                    "hi": f"उच्च लेन-देन राशि: ₹{amt:,.2f}"
                })
            if amt == round(amt) and amt > 1000:
                risk_score += 5
                result["warnings"].append({
                    "en": "Round number amount (common in scams)",
                    "hi": "गोल संख्या राशि (धोखाधड़ी में आम)"
                })
        except ValueError:
            pass
    
    result["risk_score"] = min(risk_score, 100)
    
    if not result["warnings"]:
        result["warnings"].append({
            "en": "No suspicious patterns detected in UPI intent",
            "hi": "UPI इंटेंट में कोई संदिग्ध पैटर्न नहीं पाया गया"
        })
    
    return result
