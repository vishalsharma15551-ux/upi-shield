"""
UPI Shield NLP Engine
Hybrid scam detection using Hugging Face zero-shot classification + linguistic pattern analysis.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

# Try to import transformers
try:
    from transformers import pipeline as hf_pipeline
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False
    logger.warning("transformers not installed. Using pattern-based analysis only.")


class ScamAnalyzer:
    """Hybrid NLP engine combining zero-shot classification with pattern analysis."""

    SCAM_LABELS = [
        "financial fraud or money scam",
        "urgent threat requiring immediate action",
        "impersonation of government or bank authority",
        "phishing attempt requesting sensitive information",
        "emotional manipulation or coercion",
        "legitimate normal communication",
    ]

    # ── Linguistic pattern banks (regex + semantic weight) ──────────────

    URGENCY_PATTERNS = {
        r'\b(immediate(?:ly)?|urgent(?:ly)?|right\s+now|asap)\b': 0.8,
        r'\b(within\s+\d+\s*(?:hour|minute|min|hr)s?)\b': 0.9,
        r'\b(last\s+chance|final\s+warning|deadline|expir(?:e|ing|ed))\b': 0.85,
        r'\b(don\'?t\s+delay|act\s+(?:fast|now|quickly))\b': 0.75,
        r'\b(today\s+only|limited\s+time|hurry)\b': 0.7,
        r'\b(disconnect(?:ed|ion)?|suspend(?:ed)?|block(?:ed)?|terminat(?:e|ed|ion))\b': 0.85,
        r'\b(cancel(?:led|lation)?|deactivat(?:e|ed|ion))\b': 0.8,
    }

    AUTHORITY_PATTERNS = {
        r'\b(reserve\s+bank|rbi|government|ministry)\b': 0.9,
        r'\b(police|cyber\s*cell|crime\s*branch|court|legal)\b': 0.85,
        r'\b(income\s*tax|it\s+department|gst|customs)\b': 0.9,
        r'\b(bank\s+(?:manager|officer|official)|customer\s+(?:care|support|service))\b': 0.8,
        r'\b(sbi|hdfc|icici|axis|npci|upi\s+(?:team|support))\b': 0.75,
        r'\b(electricity\s+(?:board|department|dept)|(?:bses|tata\s+power|adani))\b': 0.85,
        r'\b(telecom|(?:jio|airtel|vi|bsnl)\s+(?:support|team|officer))\b': 0.7,
    }

    PHISHING_PATTERNS = {
        r'\b(otp|pin|mpin|upi\s*pin|cvv|password|passwd)\b': 0.9,
        r'\b(card\s*number|account\s*number|ifsc|bank\s+details)\b': 0.85,
        r'\b(aadhaar|aadhar|pan\s*(?:card|number)?)\b': 0.8,
        r'\b(verify|verification|validate|confirm)\s+(?:your\s+)?(?:account|identity|details)\b': 0.75,
        r'\b(click\s+(?:here|this|the)\s+link|visit\s+(?:this|the)\s+(?:link|url|website))\b': 0.85,
        r'\b(share|send|provide|enter)\s+(?:your\s+)?(?:otp|pin|password|details)\b': 0.9,
    }

    COERCION_PATTERNS = {
        r'\b(pay|transfer|send)\s+(?:rs\.?|₹|inr)?\s*\d+': 0.8,
        r'\b(fine|penalty|fee|charge|dues)\s+of\s+(?:rs\.?|₹|inr)?\s*\d+': 0.85,
        r'\b(refund|cashback|reward|prize|lottery|won)\b': 0.75,
        r'\b(arrest(?:ed)?|jail|imprison|fir|complaint|case\s+filed)\b': 0.9,
        r'\b(money\s+laundering|tax\s+evasion|illegal|fraud\s+detected)\b': 0.85,
        r'\b(kyc\s+(?:update|expir|verif)|account\s+(?:block|suspend|freeze))\b': 0.8,
    }

    # ── Pre-authored bilingual safety messages ─────────────────────────

    SAFETY_MESSAGES = {
        "financial_fraud": {
            "en": "This message shows signs of a financial scam. No legitimate organization will ask you to urgently transfer money or share banking details.",
            "hi": "इस संदेश में वित्तीय धोखाधड़ी के संकेत हैं। कोई भी वैध संस्था आपसे तत्काल पैसे ट्रांसफर करने या बैंकिंग विवरण साझा करने को नहीं कहेगी।",
        },
        "urgency_threat": {
            "en": "This message uses urgency and fear tactics to pressure you into acting quickly. Take a moment to verify the claims independently.",
            "hi": "यह संदेश आपको जल्दी कार्रवाई करने के लिए दबाव डालने हेतु तत्कालता और भय की रणनीति का उपयोग करता है। दावों को स्वतंत्र रूप से सत्यापित करें।",
        },
        "authority_impersonation": {
            "en": "The sender is impersonating an official authority. Real authorities never ask for money or sensitive details via SMS or WhatsApp.",
            "hi": "प्रेषक अधिकारी का रूप धारण कर रहा है। असली अधिकारी कभी भी SMS/WhatsApp से पैसे या संवेदनशील जानकारी नहीं मांगते।",
        },
        "phishing": {
            "en": "This message attempts to steal your personal or financial information. Never share OTP, PIN, or passwords with anyone.",
            "hi": "यह संदेश आपकी व्यक्तिगत या वित्तीय जानकारी चुराने का प्रयास कर रहा है। कभी भी किसी को OTP, PIN या पासवर्ड साझा न करें।",
        },
        "coercion": {
            "en": "This message uses threats or emotional manipulation to force a payment. Do not act under pressure — verify independently.",
            "hi": "यह संदेश भुगतान के लिए धमकियों या भावनात्मक हेरफेर का उपयोग करता है। दबाव में कार्रवाई न करें — स्वतंत्र रूप से सत्यापित करें।",
        },
        "safe_general": {
            "en": "Always verify payment requests through official channels. Call your bank directly if in doubt.",
            "hi": "भुगतान अनुरोधों को हमेशा आधिकारिक चैनलों से सत्यापित करें। संदेह होने पर सीधे अपने बैंक को कॉल करें।",
        },
    }

    ICONS = {
        "financial_fraud": "💰", "urgency_threat": "⏰",
        "authority_impersonation": "🏛️", "phishing": "🎣",
        "coercion": "⚠️",
    }

    # ── Initialisation ─────────────────────────────────────────────────

    def __init__(self, use_transformer: bool = True):
        self.classifier = None
        self.model_loaded = False
        self.model_loading = False

        if use_transformer and HF_AVAILABLE:
            self._load_model()

    def _load_model(self):
        """Load the zero-shot classification model."""
        try:
            self.model_loading = True
            logger.info("Loading zero-shot classification model …")
            self.classifier = hf_pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                device=-1,
            )
            self.model_loaded = True
            logger.info("✓ Model loaded successfully.")
        except Exception as e:
            logger.warning(f"Model load failed ({e}). Pattern-only mode active.")
            self.model_loaded = False
        finally:
            self.model_loading = False

    # ── Public API ─────────────────────────────────────────────────────

    def get_status(self) -> Dict:
        return {
            "model_loaded": self.model_loaded,
            "model_loading": self.model_loading,
            "mode": "transformer + patterns" if self.model_loaded else "patterns only",
            "hf_available": HF_AVAILABLE,
        }

    def analyze(self, text: str) -> Dict:
        """Analyse a message and return threat assessment."""
        if not text or not text.strip():
            return self._empty_result()

        text_clean = text.strip()
        text_lower = text_clean.lower()

        # 1. Pattern analysis
        patterns = self._analyze_patterns(text_lower)

        # 2. Zero-shot classification (if available)
        zs_results = None
        if self.model_loaded and self.classifier:
            try:
                zs_results = self._zero_shot_classify(text_clean)
            except Exception as e:
                logger.error(f"Zero-shot failed: {e}")

        # 3. Composite scoring
        threat_score, cat_scores = self._compute_threat_score(patterns, zs_results)

        # 4. Threat level
        threat_level = self._get_threat_level(threat_score)

        # 5. Explanations & safety cards
        explanations = self._build_explanations(patterns, cat_scores)
        safety_cards = self._build_safety_cards(cat_scores, threat_level)
        indicators = self._collect_indicators(patterns)

        return {
            "threat_score": round(threat_score * 100),
            "threat_level": threat_level,
            "category_scores": {k: round(v * 100) for k, v in cat_scores.items()},
            "explanations": explanations,
            "safety_cards": safety_cards,
            "indicators": indicators,
            "model_used": "transformer + patterns" if self.model_loaded else "patterns only",
            "analyzed_text": text_clean[:200] + ("…" if len(text_clean) > 200 else ""),
        }

    # ── Pattern matching ───────────────────────────────────────────────

    def _analyze_patterns(self, text: str) -> Dict[str, List[Tuple[str, float]]]:
        return {
            "urgency": self._match(text, self.URGENCY_PATTERNS),
            "authority": self._match(text, self.AUTHORITY_PATTERNS),
            "phishing": self._match(text, self.PHISHING_PATTERNS),
            "coercion": self._match(text, self.COERCION_PATTERNS),
        }

    @staticmethod
    def _match(text: str, bank: Dict[str, float]) -> List[Tuple[str, float]]:
        hits: List[Tuple[str, float]] = []
        for pat, w in bank.items():
            for m in re.finditer(pat, text, re.IGNORECASE):
                hits.append((m.group(), w))
        return hits

    # ── Zero-shot classification ───────────────────────────────────────

    def _zero_shot_classify(self, text: str) -> Dict[str, float]:
        res = self.classifier(text, self.SCAM_LABELS, multi_label=True)
        return dict(zip(res["labels"], res["scores"]))

    # ── Scoring ────────────────────────────────────────────────────────

    def _compute_threat_score(
        self, patterns: Dict, zs: Optional[Dict]
    ) -> Tuple[float, Dict[str, float]]:

        cs: Dict[str, float] = {
            "financial_fraud": 0.0,
            "urgency_threat": 0.0,
            "authority_impersonation": 0.0,
            "phishing": 0.0,
            "coercion": 0.0,
        }

        mapping = {
            "urgency_threat": "urgency",
            "authority_impersonation": "authority",
            "phishing": "phishing",
            "coercion": "coercion",
        }
        for cat, pkey in mapping.items():
            hits = patterns.get(pkey, [])
            if hits:
                mx = max(w for _, w in hits)
                cf = min(len(hits) / 5.0, 1.0)
                cs[cat] = mx * 0.7 + cf * 0.3

        # Financial fraud is derived
        cs["financial_fraud"] = max(
            cs["phishing"] * 0.8,
            cs["coercion"] * 0.9,
            (cs["urgency_threat"] + cs["authority_impersonation"]) / 2 * 0.7,
        )

        # Blend with zero-shot scores
        if zs:
            zs_map = {
                "financial fraud or money scam": "financial_fraud",
                "urgent threat requiring immediate action": "urgency_threat",
                "impersonation of government or bank authority": "authority_impersonation",
                "phishing attempt requesting sensitive information": "phishing",
                "emotional manipulation or coercion": "coercion",
            }
            for zl, cat in zs_map.items():
                zsc = zs.get(zl, 0.0)
                ps = cs[cat]
                cs[cat] = (ps * 0.4 + zsc * 0.6) if ps > 0 else zsc * 0.5

            legit = zs.get("legitimate normal communication", 0.0)
            if legit > 0.7:
                for k in cs:
                    cs[k] *= 1.0 - legit * 0.5

        weights = {
            "financial_fraud": 1.0, "urgency_threat": 0.7,
            "authority_impersonation": 0.85, "phishing": 0.95, "coercion": 0.9,
        }
        ws = [cs[c] * weights[c] for c in cs]
        mx = max(ws) if ws else 0.0
        av = sum(ws) / len(ws) if ws else 0.0
        return min(mx * 0.7 + av * 0.3, 1.0), cs

    @staticmethod
    def _get_threat_level(score: float) -> str:
        if score >= 0.75: return "CRITICAL"
        if score >= 0.50: return "HIGH"
        if score >= 0.25: return "MEDIUM"
        return "LOW"

    # ── Explanation generation ─────────────────────────────────────────

    def _build_explanations(self, patterns, cs) -> List[Dict]:
        out: List[Dict] = []
        defs = [
            ("urgency_threat", "urgency", "Urgency Tactics", "तत्कालता की रणनीति",
             "Uses urgency-inducing language", "तत्कालता पैदा करने वाली भाषा का उपयोग"),
            ("authority_impersonation", "authority", "Authority Impersonation",
             "अधिकार का दुरुपयोग", "Claims to be from", "होने का दावा करता है"),
            ("phishing", "phishing", "Information Theft", "सूचना चोरी",
             "Asks for sensitive data", "संवेदनशील डेटा मांगता है"),
            ("coercion", "coercion", "Financial Coercion", "वित्तीय दबाव",
             "Pressures financial action", "वित्तीय कार्रवाई का दबाव"),
        ]
        for cat, pkey, title, title_hi, desc, desc_hi in defs:
            if cs.get(cat, 0) > 0.3:
                terms = [m[0] for m in patterns.get(pkey, [])[:3]]
                t = ", ".join(terms) if terms else "detected"
                out.append({
                    "category": title, "category_hi": title_hi,
                    "description": f"{desc}: {t}",
                    "description_hi": f"{desc_hi}: {t}",
                    "severity": "high" if cs[cat] > 0.6 else "medium",
                })

        if cs.get("financial_fraud", 0) > 0.3 and not any(
            e["category"] in ("Financial Coercion", "Information Theft") for e in out
        ):
            out.append({
                "category": "Financial Fraud Risk",
                "category_hi": "वित्तीय धोखाधड़ी का जोखिम",
                "description": "Multiple scam indicators detected in this message.",
                "description_hi": "इस संदेश में कई धोखाधड़ी संकेतक पाए गए।",
                "severity": "high" if cs["financial_fraud"] > 0.6 else "medium",
            })

        if not out:
            out.append({
                "category": "Analysis Complete",
                "category_hi": "विश्लेषण पूर्ण",
                "description": "No significant scam indicators detected. Stay cautious with financial messages.",
                "description_hi": "कोई महत्वपूर्ण धोखाधड़ी संकेतक नहीं पाए गए। वित्तीय संदेशों के साथ सतर्क रहें।",
                "severity": "low",
            })
        return out

    def _build_safety_cards(self, cs, level) -> List[Dict]:
        cards: List[Dict] = []
        if level in ("CRITICAL", "HIGH"):
            for cat, score in sorted(cs.items(), key=lambda x: x[1], reverse=True)[:3]:
                if score > 0.3 and cat in self.SAFETY_MESSAGES:
                    cards.append({
                        "type": cat,
                        "en": self.SAFETY_MESSAGES[cat]["en"],
                        "hi": self.SAFETY_MESSAGES[cat]["hi"],
                        "icon": self.ICONS.get(cat, "🔍"),
                    })
            cards.append({
                "type": "safe_general",
                "en": self.SAFETY_MESSAGES["safe_general"]["en"],
                "hi": self.SAFETY_MESSAGES["safe_general"]["hi"],
                "icon": "🛡️",
            })
        elif level == "MEDIUM":
            top = max(cs, key=cs.get)
            if top in self.SAFETY_MESSAGES:
                cards.append({
                    "type": top,
                    "en": self.SAFETY_MESSAGES[top]["en"],
                    "hi": self.SAFETY_MESSAGES[top]["hi"],
                    "icon": self.ICONS.get(top, "🔍"),
                })
            cards.append({
                "type": "safe_general",
                "en": self.SAFETY_MESSAGES["safe_general"]["en"],
                "hi": self.SAFETY_MESSAGES["safe_general"]["hi"],
                "icon": "🛡️",
            })
        else:
            cards.append({
                "type": "safe",
                "en": "This message appears relatively safe. Always stay vigilant with financial communications.",
                "hi": "यह संदेश अपेक्षाकृत सुरक्षित प्रतीत होता है। वित्तीय संचार के साथ हमेशा सतर्क रहें।",
                "icon": "✅",
            })
        return cards

    @staticmethod
    def _collect_indicators(patterns) -> List[Dict]:
        out = []
        for cat, hits in patterns.items():
            for term, w in hits:
                out.append({"term": term, "category": cat, "weight": round(w, 2)})
        return out

    def _empty_result(self):
        return {
            "threat_score": 0, "threat_level": "LOW",
            "category_scores": {}, "explanations": [{
                "category": "No Input", "category_hi": "कोई इनपुट नहीं",
                "description": "Please provide a message to analyze.",
                "description_hi": "कृपया विश्लेषण के लिए एक संदेश प्रदान करें।",
                "severity": "low",
            }],
            "safety_cards": [], "indicators": [],
            "model_used": "none", "analyzed_text": "",
        }
