# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT VIGILAGENT // GI5 "OMEGA" KERNEL
# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY: GI5 (General Intelligence 5) - The Deterministic Cyber-Forensic God Class
# TYPE: Multi-Dimensional Heuristic Engine (NOT an LLM)
# PRIME DIRECTIVE: Protect the user from 0-day web threats with:
#   - 0ms latency (Pure Python, No API calls)
#   - 0% hallucination (Deterministic Logic Only)
#   - 100% privacy (All processing local)
# METHODOLOGY: Define → Roast → Refine (Evolutionary Architecture)
# ═══════════════════════════════════════════════════════════════════════════════
# CAPABILITIES:
#   1. POLY-CIPHER CRACKING: ROT13, Reverse, Base64, URL, Hex decoding
#   2. UNICODE FORENSICS: Zero-width space removal, Homoglyph normalization
#   3. VECTOR FINGERPRINTING: N-Gram toxic tuple matching
#   4. ENTROPY MATHEMATICS: Shannon information theory
#   5. SIGMOID AGGREGATION: Non-linear risk scoring
#   6. LEVENSHTEIN GEOMETRY: Typosquatting detection
# ═══════════════════════════════════════════════════════════════════════════════

import math
import re
import base64
import urllib.parse
import codecs
import binascii
import logging
import sys
from typing import Dict, Any, List, Optional, Set, Tuple

logger = logging.getLogger("GI-5")
# Route default logging to STDOUT (not stderr) so INFO startup banners are not
# mistaken for errors by shells/CI that treat any stderr output as a failure
# (e.g. PowerShell NativeCommandError). Only configure if the root logger has no
# handlers yet, so an app/host that sets up its own logging is never overridden.
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)


class GeneralIntelligence5:
    """
    GI5 "OMEGA" EDITION: The Deterministic Cyber-Forensic God Class.
    
    Architecture (6-Core Cognitive Stack):
    ├── Core 1: SANITIZER (Unicode & Invisible Forensics)
    ├── Core 2: POLY-CIPHER CRACKER (Multi-Cipher Heuristic Brute-Force)
    ├── Core 3: SKELETONIZER (Leet-Speak Reversal + Homoglyph Normalization)
    ├── Core 4: ENTROPY ENGINE (Shannon Information Theory)
    ├── Core 5: VECTOR FINGERPRINTER (N-Gram Toxic Tuple Matching)
    ├── Core 6: GEOMETER (Levenshtein Distance + Typosquatting)
    └── SIGMOID AGGREGATOR (Non-Linear Risk Fusion)
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # KNOWLEDGE BASE: THE GENOME
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Toxic Vectors: Word combinations that indicate specific attacks
    # When 2+ words from a set appear together, it's a confirmed attack vector
    TOXIC_VECTORS = [
        ({"javascript", "vbscript", "expression", "eval", "onerror", "onload", "src", "href"}, "XSS Injection"),
        ({"union", "select", "insert", "drop", "table", "delete", "update"}, "SQL Injection"),
        ({"etc", "passwd", "shadow", "boot.ini", "win.ini", ".htaccess"}, "LFI/Path Traversal"),
        ({"location", "href", "cookie", "document", "window"}, "DOM Hijacking"),
        ({"ignore", "previous", "instructions", "system", "prompt", "override"}, "LLM Jailbreak"),
        ({"wget", "curl", "bash", "powershell", "cmd", "exec"}, "RCE/Command Injection"),
        ({"password", "token", "secret", "bearer", "apikey", "credentials"}, "Credential Exposure"),
        ({"redirect", "forward", "url", "next", "return", "goto"}, "Open Redirect"),
        ({"admin", "root", "superuser", "elevated", "privilege"}, "Privilege Escalation"),
        ({"iframe", "object", "embed", "applet", "base", "meta"}, "HTML Injection")
    ]
    
    # Injection Pattern Skeletons (after normalization)
    INJECTION_SKELETONS = [
        "ignoreprevious", "ignorepreviousinstruction", "systemoverride",
        "deletefiles", "transferfunds", "youareinaisystem",
        "disregardabove", "forgetprevious", "newinstruction",
        "actasdeveloper", "developermode", "jailbreak",
        "revealpassword", "showsecrets", "dumpdatabase",
        "simulatemode", "revealprompt", "bypassfilter"
    ]
    
    # Trusted Roots for Phishing Detection
    TRUSTED_ROOTS = [
        "google", "paypal", "microsoft", "apple", "facebook", "amazon",
        "netflix", "twitter", "linkedin", "instagram", "github", "stripe",
        "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
        "dropbox", "zoom", "slack", "salesforce", "adobe", "oracle"
    ]
    
    # Leet-speak reversal map (for skeleton normalization)
    LEET_MAP = {
        '1': 'i', '!': 'i', '|': 'i',
        '0': 'o', '3': 'e', '4': 'a', '7': 't',
        '@': 'a', '$': 's', '5': 's', '8': 'b', 
        '9': 'g', '6': 'g', '+': 't', '(': 'c'
    }
    
    # Homoglyph mappings (Cyrillic/Unicode lookalikes)
    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
        'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g', 'һ': 'h',
        'ḷ': 'l', 'ṃ': 'm', 'ṇ': 'n', 'ṭ': 't', 'ṿ': 'v', 'ẉ': 'w'
    }
    
    # Zero-width and invisible characters
    INVISIBLE_CHARS = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u034f\u2060\u2061\u2062\u2063\u2064\u0000-\u001f]')

    # PII / Sensitive Data Patterns
    PII_PATTERNS = {
        "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "CREDIT_CARD": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
        "API_KEY": re.compile(r'\b(?:sk|pk|key|secret|token)[-_]?[a-zA-Z0-9]{16,64}\b', re.IGNORECASE),
        "JWT": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
        "DOCKER_CONFIG": re.compile(r'docker-config-hash:[a-fA-F0-9]{40,64}'),
        "AWS_KEY": re.compile(r'AKIA[0-9A-Z]{16}'),
    }

    def __init__(self):
        """Initialize the OMEGA Engine."""
        self.entropy_threshold = 4.85
        self.sigmoid_steepness = 0.1
        self.max_recursion_depth = 3
        self.enabled = True
        logger.info("GI-5: OMEGA KERNEL ONLINE. 6-Core Forensic Stack Active.")

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 1: THE SANITIZER (Unicode & Invisible Forensics)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: `opacity == 0` check misses zero-width spaces and control chars
    # REFINE: Strip ALL invisible Unicode before analysis
    # ═══════════════════════════════════════════════════════════════════════════

    def _sanitize_input(self, text: str) -> str:
        """
        Removes invisible attacks: Zero-width spaces, control characters,
        directional formatting, and soft hyphens.
        
        Example: 'p\u200bass\u200bword' → 'password'
        """
        if not text:
            return ""
        
        # Step 1: Remove all invisible/zero-width characters
        clean = self.INVISIBLE_CHARS.sub('', text)
        
        # Step 2: Normalize homoglyphs (Cyrillic lookalikes → Latin)
        for glyph, replacement in self.HOMOGLYPHS.items():
            clean = clean.replace(glyph, replacement)
        
        return clean

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 2: THE POLY-CIPHER CRACKER (Multi-Cipher Heuristic Brute-Force)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: Standard decoders only check Base64. Hackers use ROT13, Reverse, XOR
    # REFINE: Attempt ALL common ciphers and collect decoded variants
    # ═══════════════════════════════════════════════════════════════════════════

    def _heuristic_crack(self, text: str) -> Set[str]:
        """
        Attempts to break common obfuscation layers:
        - ROT13 (Caesar cipher variant)
        - Reverse String
        - Base64 (recursive up to 3 levels)
        - URL Encoding (recursive)
        - Hex Encoding
        
        Returns a set of ALL revealed variations for analysis.
        """
        candidates = {text}
        
        if not text or len(text) < 4:
            return candidates
        
        # 1. REVERSE STRING ("tpircsavaj" → "javascript")
        reversed_text = text[::-1]
        candidates.add(reversed_text)
        
        # 2. ROT13 (Caesar Cipher - shifts letters 13 positions)
        try:
            rot13_decoded = codecs.encode(text, 'rot_13')
            candidates.add(rot13_decoded)
        except Exception as e:
            logger.debug("ROT13 decode failed: %s", e)
        
        # 3. RECURSIVE DECODING LOOP (Base64, URL, Hex)
        current = text
        for depth in range(self.max_recursion_depth):
            decoded_something = False
            
            # A. URL Decode
            try:
                url_decoded = urllib.parse.unquote(current)
                if url_decoded != current and len(url_decoded) > 4:
                    candidates.add(url_decoded)
                    current = url_decoded
                    decoded_something = True
            except Exception as e:
                logger.debug("URL decode failed at depth %d: %s", depth, e)
            
            # B. Base64 Decode
            if not decoded_something:
                try:
                    # Auto-fix padding
                    padded = current + '=' * (-len(current) % 4)
                    b64_decoded = base64.b64decode(padded, validate=False).decode('utf-8', errors='ignore')
                    if b64_decoded and b64_decoded.isprintable() and len(b64_decoded) > 4:
                        candidates.add(b64_decoded)
                        current = b64_decoded
                        decoded_something = True
                except Exception as e:
                    logger.debug("Base64 decode failed at depth %d: %s", depth, e)
            
            # C. Hex Decode
            if not decoded_something:
                try:
                    hex_decoded = bytes.fromhex(current).decode('utf-8', errors='ignore')
                    if hex_decoded and len(hex_decoded) > 4:
                        candidates.add(hex_decoded)
                        current = hex_decoded
                        decoded_something = True
                except Exception as e:
                    logger.debug("Hex decode failed at depth %d: %s", depth, e)
            
            if not decoded_something:
                break
        
        return candidates

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 3: THE SKELETONIZER (Leet-Speak Reversal + Normalization)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: Regex fails on "p@$$w0rd!" and "1gn0r3 pr3v10us"
    # REFINE: Skeleton Key Normalization strips to semantic core
    # ═══════════════════════════════════════════════════════════════════════════

    def _normalize_skeleton(self, text: str) -> str:
        """
        Strips text to its semantic bones for pattern matching.
        
        Pipeline:
        1. Lowercase
        2. Reverse leet-speak substitutions
        3. Strip all non-alphanumeric
        
        Example: 'P@$$w0rd!' → 'password'
        Example: '1gn0r3 pr3v10us 1nstruct10ns' → 'ignorepreviousinstructions'
        """
        if not text:
            return ""
        
        result = text.lower()
        
        # Leet-speak reversal
        for leet, replacement in self.LEET_MAP.items():
            result = result.replace(leet, replacement)
        
        # Strip non-alphanumeric
        result = re.sub(r'[^a-z0-9]', '', result)
        
        return result

    def _scan_injection_patterns(self, text: str) -> Tuple[bool, str]:
        """Scans normalized text for injection pattern skeletons."""
        skeleton = self._normalize_skeleton(text)
        
        for pattern in self.INJECTION_SKELETONS:
            if pattern in skeleton:
                return (True, pattern)
        
        return (False, "")

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 4: THE ENTROPY ENGINE (Shannon Information Theory)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: "too long" and "looks weird" are not metrics
    # REFINE: Shannon Entropy mathematically distinguishes information from chaos
    # ═══════════════════════════════════════════════════════════════════════════

    def _calculate_entropy(self, text: str) -> float:
        """
        Shannon Entropy: Mathematical measurement of information density.
        
        Formula: H(x) = -Σ p(x) * log₂(p(x))
        
        Thresholds:
        - English Normal: ~3.5 to 4.5 bits/symbol
        - Malicious/Obfuscated (Base64, encrypted): > 4.85 bits/symbol
        """
        if not text or len(text) < 2:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 5: THE VECTOR FINGERPRINTER (N-Gram Toxic Tuple Matching)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: High syntax density just means "it's code" - too many false positives
    # REFINE: Look for TOXIC TUPLES - word combinations that indicate attacks
    # ═══════════════════════════════════════════════════════════════════════════

    def _vector_scan(self, text: str) -> Tuple[int, str]:
        """
        Scans text against Toxic Vectors (N-Gram fingerprints).
        
        Instead of just counting symbols, we look for toxic word combinations:
        - Safe: "function() {" 
        - Toxic: "onerror" + "alert" + "document.cookie"
        
        Returns (risk_weight, threat_description)
        """
        normalized = text.lower()
        max_risk = 0
        detected_threat = ""
        
        for vector_set, threat_name in self.TOXIC_VECTORS:
            # Count how many words from the toxic vector are present
            hits = sum(1 for word in vector_set if word in normalized)
            
            # If 2+ words from the vector are present, it's a match
            if hits >= 2:
                risk = 70 + (hits * 10)  # Base 70, +10 per hit
                if risk > max_risk:
                    max_risk = min(risk, 100)  # Cap at 100
                    detected_threat = f"{threat_name} ({hits} vector matches)"
        
        return max_risk, detected_threat

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE 6: THE GEOMETER (Levenshtein Distance + Typosquatting)
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: Blacklists are useless - hackers create 10,000 domains/day
    # REFINE: Detect domains PRETENDING to be trusted roots
    # ═══════════════════════════════════════════════════════════════════════════

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """
        Levenshtein Edit Distance: Minimum single-character edits to transform s1 → s2.
        
        Used for typosquatting detection:
        - "g00gle" is 2 edits from "google"
        - If distance < 3 AND domain != trusted, it's phishing
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    def _detect_typosquatting(self, domain: str) -> Optional[Tuple[bool, str, int]]:
        """Detects if a domain is attempting to impersonate a trusted root.

        Returns None when no match is found, or (True, impersonated_trusted_root, edit_distance).
        Using None instead of (False, "", 0) avoids the Python truthiness bug where
        a non-empty tuple is always truthy, causing every domain to be falsely flagged.
        Callers should unpack: result = gi5._detect_typosquatting(domain)
                                  if result is not None: is_typo, name, dist = result
        """
        if not domain:
            return None
        
        # Normalize and extract root
        normalized = self._normalize_skeleton(domain)
        root = normalized.split('.')[0] if '.' in domain else normalized
        root = re.sub(r'(com|org|net|io|co|uk|de|fr|app|dev)$', '', root)
        
        for trusted in self.TRUSTED_ROOTS:
            if root == trusted:
                continue
            
            distance = self._levenshtein_distance(root, trusted)
            
            if 0 < distance <= 2:
                return (True, trusted, distance)
            
            if trusted in root and root != trusted:
                return (True, trusted, 1)
        
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # SIGMOID AGGREGATOR: Non-Linear Risk Fusion
    # ═══════════════════════════════════════════════════════════════════════════
    # ROAST: Linear math is dumb. Two "Low Risk" signals are often MORE dangerous
    # REFINE: Sigmoid activation function for non-linear aggregation
    # ═══════════════════════════════════════════════════════════════════════════

    def _sigmoid_score(self, inputs: List[float]) -> int:
        """
        Non-Linear Risk Aggregation using Sigmoid activation.
        
        Multiple weak signals compound exponentially:
        - Hidden element (30) + High entropy (40) = 70 linear
        - But sigmoid knows 2 risks together are worse: outputs ~95
        
        Formula: 100 / (1 + e^(-k * (x - threshold)))
        """
        if not inputs:
            return 0
        
        total_weight = sum(inputs)
        
        # Sigmoid: shifts curve so ~40 triggers warning, ~70 triggers block
        score = 100 / (1 + math.exp(-self.sigmoid_steepness * (total_weight - 40)))
        
        return int(min(score, 100))

    def analyze_sensitivity(self, text: str) -> List[str]:
        """
        Deterministic Sensitivity Analysis (PII/Secret Detection).
        Uses high-speed regex patterns to find common sensitive data types.
        """
        if not text:
            return []
        
        detected = []
        # Scan variants for deobfuscated PII
        clean = self._sanitize_input(text)
        variants = self._heuristic_crack(clean)
        
        all_text = " ".join(variants)
        for label, pattern in self.PII_PATTERNS.items():
            if pattern.search(all_text):
                detected.append(label)
        
        return detected

    # ═══════════════════════════════════════════════════════════════════════════
    # MASTER PROCESSOR: UNIFIED THREAT ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════════

    def analyze_threat(self, payload):
        """Analyze a threat payload. Accepts dict or string input."""
        # FIX: Handle string payloads gracefully
        if isinstance(payload, str):
            payload = {"text": payload}
        if not isinstance(payload, dict):
            payload = {"text": str(payload)}
        """
        The OMEGA Processor.
        
        Flow: Sanitize → Crack → Skeletonize → Vector Scan → Entropy → Geometry → Sigmoid
        
        Input payload can contain:
        - text: String content to analyze
        - domain: URL/domain to check for typosquatting
        - hidden: Boolean indicating if element is hidden (adds risk weight)
        - element: DOM element data for visual analysis
        
        Returns verdict with full forensic reasoning chain.
        """
        raw_text = payload.get("text", "")
        domain = payload.get("domain", "")
        is_hidden = payload.get("hidden", False)
        element = payload.get("element", {})
        
        # Risk Accumulator (Collects signals from all cores)
        risk_signals: List[float] = []
        verdicts: List[str] = []
        
        # ─── PHASE 1: SANITIZATION ───
        clean_text = self._sanitize_input(raw_text)
        
        # ─── PHASE 2: POLY-CIPHER CRACKING ───
        # Attempt to decode all obfuscation layers
        candidates = self._heuristic_crack(clean_text)
        
        for variant in candidates:
            # ─── CHECK A: SKELETON PATTERN MATCHING ───
            is_injection, pattern = self._scan_injection_patterns(variant)
            if is_injection:
                risk_signals.append(100)
                verdicts.append(f"Injection Pattern: '{pattern}'")
            
            # ─── CHECK B: VECTOR FINGERPRINTING ───
            vector_risk, vector_name = self._vector_scan(variant)
            if vector_risk > 0:
                risk_signals.append(vector_risk)
                verdicts.append(f"Vector Match: {vector_name}")
            
            # ─── CHECK C: ENTROPY ANALYSIS ───
            if len(variant) > 25:
                entropy = self._calculate_entropy(variant)
                if entropy > self.entropy_threshold:
                    risk_signals.append(40)
                    verdicts.append(f"High Entropy: {entropy:.2f} bits/sym")
            
            # ─── CHECK D: SYNTAX DENSITY ───
            if len(variant) > 10:
                code_chars = len(re.findall(r'[;{}\(\)<>\$\[\]=]', variant))
                syntax_density = code_chars / len(variant)
                if syntax_density > 0.25:
                    risk_signals.append(50)
                    verdicts.append(f"Syntax Density: {syntax_density:.0%}")
        
        # ─── PHASE 3: TYPOSQUATTING DETECTION ───
        if domain:
            typosquat_result = self._detect_typosquatting(domain)
            if typosquat_result is not None:
                is_typosquat, impersonated, distance = typosquat_result
                risk_signals.append(95)
                verdicts.append(f"Phishing: Mimics '{impersonated}' (distance: {distance})")
        
        # ─── PHASE 4: CONTEXT SIGNALS ───
        if is_hidden:
            risk_signals.append(30)
            verdicts.append("Hidden Element")
        
        # ─── PHASE 5: DOM GEOMETRY ANALYSIS ───
        if element:
            styles = element.get("styles", {})
            
            opacity = float(styles.get("opacity", 1.0))
            if opacity < 0.1:
                risk_signals.append(40)
                verdicts.append("Invisible Overlay")
            
            z_index = int(styles.get("z-index", 0) or 0)
            if z_index > 9000:
                risk_signals.append(30)
                verdicts.append("Z-Index Overlay Attack")
        
        # ─── PHASE 6: SIGMOID AGGREGATION ───
        final_score = self._sigmoid_score(risk_signals)
        
        # ─── DETERMINISTIC VERDICT ───
        if final_score >= 75:
            return {
                "verdict": "BLOCK",
                "risk_score": final_score,
                "layer": "OMEGA",
                "reason": " | ".join(verdicts) if verdicts else "Heuristic Anomaly Aggregation"
            }
        elif final_score >= 50:
            return {
                "verdict": "WARN",
                "risk_score": final_score,
                "layer": "OMEGA",
                "reason": "Potential Risk: " + (" | ".join(verdicts) if verdicts else "Elevated Signals")
            }
        
        return {
            "verdict": "ALLOW",
            "risk_score": final_score,
            "layer": "OMEGA",
            "reason": "GI5 OMEGA: All Cores Verified Safe"
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # LEGACY COMPATIBILITY LAYER
    # ═══════════════════════════════════════════════════════════════════════════

    def synthesize_payloads(self, base_request):
        """Synthesize attack payloads. Accepts dict or string input."""
        if isinstance(base_request, str):
            base_request = {"text": base_request}
        if not isinstance(base_request, dict):
            base_request = {"text": str(base_request)}
        """Legacy: Generates attack payload variants."""
        logger.info("GI-5: Synthesizing payload variants...")
        return [
            {"name": "Negative Logic", "json": {"amount": -100, "qty": -1}},
            {"name": "Integer Overflow", "json": {"amount": 9999999999999}},
            {"name": "SQL Injection", "json": {"username": "' OR 1=1--"}},
            {"name": "NoSQL Injection", "json": {"username": {"$ne": None}}},
            {"name": "Mass Assignment", "json": {"role": "admin", "is_admin": True}},
            {"name": "XSS Payload", "json": {"name": "<script>alert('XSS')</script>"}},
            {"name": "Path Traversal", "json": {"file": "../../../etc/passwd"}}
        ]

    def predict_race_window(self, headers: Dict[str, str]) -> float:
        """Legacy: Predicts optimal race condition delay."""
        server = headers.get("Server", "").lower()
        if "nginx" in server or "apache" in server:
            return 7.5
        return 3.0

    def generate_forensic_report_block(self, vulnerability_data: Dict[str, Any]) -> str:
        """Legacy: Generates forensic report block."""
        return f"""
::TITLE:: [{vulnerability_data.get('severity', 'Medium')}] {vulnerability_data.get('type', 'Unknown')}
::EVIDENCE:: {vulnerability_data.get('payload', 'N/A')}
::REMEDIATION:: Review and patch the affected endpoint.
"""


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

# Primary Instance (OMEGA Kernel)
brain = GeneralIntelligence5()

# Legacy Alias
GI5Engine = GeneralIntelligence5

# Backward-compatible alias (FIX)
GI5Kernel = GI5Engine
