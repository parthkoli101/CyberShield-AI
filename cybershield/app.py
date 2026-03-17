"""
CyberShield AI — Backend Server
Supports: Groq (free) + Anthropic Claude
Key is auto-detected from prefix:
  gsk_...    → Groq
  sk-ant-... → Anthropic

Run:   python app.py
Open:  http://localhost:5000
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, json, math, re, urllib.request, urllib.error
from datetime import datetime

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)


# ═══════════════════════════════════════════════════════
#  PROVIDER LAYER — Groq or Anthropic, same interface
# ═══════════════════════════════════════════════════════

GROQ_MODEL      = "llama-3.3-70b-versatile"
ANTHROPIC_MODEL = "claude-3-5-sonnet-20240620"


def detect_provider(api_key: str) -> str:
    if not api_key:
        raise ValueError("No API key provided. Paste your key in the header.")
    k = api_key.strip()
    if k.startswith("gsk_"):    return "groq"
    if k.startswith("sk-ant"):  return "anthropic"
    return "groq"


def _parse_response(text: str) -> dict:
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*",     "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
        return {
            "risk": "MEDIUM", "score": 50, "confidence": 60,
            "verdict": "Analysis complete",
            "explanation": text[:800],
            "indicators": [], "actions": ["Review manually"],
        }


def _call_groq(system_prompt: str, user_content: str, api_key: str) -> dict:
    payload = json.dumps({
        "model":       GROQ_MODEL,
        "messages":    [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ],
        "max_tokens":  2048,
        "temperature": 0.1,
    }).encode("utf-8")
    
    # ADDED: User-Agent header to bypass Cloudflare 403 blocks
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberShieldAI/1.0"
    }
    
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return _parse_response(data["choices"][0]["message"]["content"])
    except urllib.error.HTTPError as e:
        raise ValueError(f"Groq error {e.code}: {e.read().decode()}")


def _call_anthropic(system_prompt: str, user_content: str, api_key: str) -> dict:
    payload = json.dumps({
        "model":       ANTHROPIC_MODEL,
        "max_tokens": 2048,
        "system":     system_prompt,
        "messages":   [{"role": "user", "content": user_content}],
    }).encode("utf-8")
    
    # ADDED: User-Agent header for consistency
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "User-Agent": "Mozilla/5.0 CyberShieldAI/1.0"
    }
    
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return _parse_response(data["content"][0]["text"])
    except urllib.error.HTTPError as e:
        raise ValueError(f"Anthropic error {e.code}: {e.read().decode()}")


def call_ai(system_prompt: str, user_content: str, api_key: str) -> dict:
    provider = detect_provider(api_key)
    if provider == "groq":
        return _call_groq(system_prompt, user_content, api_key)
    return _call_anthropic(system_prompt, user_content, api_key)


def get_api_key(data: dict) -> str:
    return (data.get("api_key", "")
            or os.environ.get("GROQ_API_KEY", "")
            or os.environ.get("ANTHROPIC_API_KEY", ""))


# ═══════════════════════════════════════════════════════
#  LOCAL ANALYSIS — zero API cost
# ═══════════════════════════════════════════════════════

def shannon_entropy(text: str) -> float:
    if not text: return 0.0
    freq = {}
    for ch in text: freq[ch] = freq.get(ch, 0) + 1
    return -sum((f/len(text))*math.log2(f/len(text)) for f in freq.values())


def analyze_url_locally(url: str) -> dict:
    flags, u = [], url.lower()
    entropy  = round(shannon_entropy(url), 2)
    if entropy > 4.5:
        flags.append({"type":"bad",  "label":f"High entropy: {entropy} — obfuscation likely"})
    if len(url) > 100:
        flags.append({"type":"warn", "label":f"Unusually long URL ({len(url)} chars)"})
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        flags.append({"type":"bad",  "label":"Raw IP address instead of domain"})
    for kw in ["login","verify","account","secure","update","confirm",
                "paypal","amazon","bank","suspend","urgent","free","winner"]:
        if kw in u:
            flags.append({"type":"warn","label":f'Suspicious keyword: "{kw}"'}); break
    domain_part = url.split("/")[2] if "//" in url else url.split("/")[0]
    parts = domain_part.split(".")
    if len(parts) > 4:
        flags.append({"type":"warn","label":f"Excessive subdomains ({len(parts)} levels)"})
    tld = parts[-1].split("?")[0] if parts else ""
    if tld in ["xyz","ru","tk","ml","ga","cf","gq","top","click","pw"]:
        flags.append({"type":"bad","label":f"High-risk TLD: .{tld}"})
    if url.startswith("http://"):
        flags.append({"type":"warn","label":"No HTTPS — plaintext connection"})
    for brand in ["google","paypal","amazon","facebook","microsoft","apple",
                  "netflix","instagram","twitter","hdfc","sbi","icici"]:
        if brand[:-1] in u and brand not in u:
            flags.append({"type":"bad","label":f'Possible typosquatting of "{brand}"'})
    if "@" in url:
        flags.append({"type":"bad","label":"@ symbol in URL — credential theft trick"})
    if url.count("-") > 4:
        flags.append({"type":"warn","label":f"Excessive hyphens ({url.count('-')})"})
    if re.search(r"%[0-9a-fA-F]{2}", url):
        flags.append({"type":"warn","label":"URL-encoded characters detected"})
    if re.search(r"(redirect|url|next|return|goto)=http", u):
        flags.append({"type":"bad","label":"Open redirect parameter detected"})
    if not flags:
        flags.append({"type":"ok","label":"No obvious structural red flags"})
    return {"flags":flags,"entropy":entropy,"length":len(url),"domain":domain_part}


def analyze_email_heuristics(text: str) -> dict:
    tl, signals = text.lower(), []
    found = [w for w in ["urgent","immediately","suspended","verify now","expires",
                         "24 hours","act now","account locked","click here"] if w in tl]
    if found:
        signals.append({"severity":"red","label":f"Urgency language: {', '.join(found[:3])}"})
    urls     = re.findall(r'https?://\S+', text)
    bad_urls = [u for u in urls if any(t in u.lower()
                for t in [".xyz",".tk",".ru","secure-","verify-","login-"])]
    if bad_urls:
        signals.append({"severity":"red","label":f"Suspicious URL: {bad_urls[0][:60]}"})
    elif urls:
        signals.append({"severity":"orange","label":f"{len(urls)} URL(s) in email"})
    amounts = re.findall(r'\$[\d,]+', text)
    if amounts:
        signals.append({"severity":"orange","label":f"Financial amounts: {', '.join(amounts[:3])}"})
    brands = ["paypal","amazon","google","microsoft","apple","facebook","bank","netflix"]
    for brand in brands:
        if brand in tl:
            signals.append({"severity":"orange","label":f'Brand mention: "{brand}"'}); break
    fm = re.search(r"from:\s*(.+)", text, re.IGNORECASE)
    if fm:
        dm = re.search(r"@([\w.-]+)", fm.group(1))
        if dm:
            sd = dm.group(1).lower()
            for brand in brands[:6]:
                if brand in tl and brand not in sd:
                    signals.append({"severity":"red",
                                    "label":f"Domain mismatch: claims {brand}, from @{sd}"}); break
    if re.search(r"(password|credential|bank account|credit card)", tl):
        signals.append({"severity":"red","label":"Requests sensitive personal data"})
    if re.search(r"(do not tell|keep confidential|don't discuss|between us)", tl):
        signals.append({"severity":"red","label":"Secrecy instruction — social engineering"})
    return {"signals":signals,"url_count":len(urls),"found_urls":urls[:5]}


def analyze_prompt_locally(text: str) -> dict:
    patterns = {
        "JAILBREAK":           [r"ignore (all |previous |prior )?(instructions?|rules?)",
                                r"\bDAN\b", r"do anything now", r"jailbreak",
                                r"you are now (an? )?(unrestricted|free|unchained)"],
        "ROLE_OVERRIDE":       [r"act as (a |an )?(?!assistant)",
                                r"(roleplay|role-play) as",
                                r"(forget|ignore) (that )?you('re| are) (an? )?AI",
                                r"(admin|developer|god) mode"],
        "INSTRUCTION_BYPASS":   [r"(override|bypass|disable) (safety|filter|restriction)",
                                r"(new|updated|secret) (system )?prompt",
                                r"\[SYSTEM\]|\[INST\]|\[ADMIN\]",
                                r"ignore the (above|previous|prior)"],
        "INDIRECT_INJECTION":   [r"(hidden|invisible) instruction", r"summarize.*ignore"],
    }
    matched = {}
    for cat, pats in patterns.items():
        for p in pats:
            if re.search(p, text, re.IGNORECASE):
                matched[cat] = matched.get(cat, 0) + 1
    return {"matched_categories": matched,
            "injection_type":     max(matched, key=matched.get) if matched else "CLEAN",
            "local_severity":     min(100, sum(matched.values()) * 20),
            "total_matches":      sum(matched.values())}


# ═══════════════════════════════════════════════════════
#  SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════

EMAIL_SYS = """You are CyberShield AI, an expert email threat analyst.
Return ONLY a raw JSON object. No markdown. No text outside JSON. Start with { end with }.
{
  "risk":"HIGH|MEDIUM|LOW","score":<0-100>,"confidence":<0-100>,
  "verdict":"<one line>",
  "attack_type":"<Phishing|CEO Fraud|Invoice Fraud|Credential Harvesting|Spam|Benign>",
  "indicators":[{"severity":"red|orange|green","label":"<observable>"}],
  "highlighted":"<most suspicious phrase or NONE>",
  "sender_analysis":"<From address analysis>",
  "url_found":"<suspicious URL or NONE>",
  "explanation":"<2-3 paragraphs: techniques, attacker goal, evidence>",
  "actions":["<action1>","<action2>","<action3>"]
}"""

URL_SYS = """You are CyberShield AI URL threat engine.
Return ONLY raw JSON. No markdown. Start with { end with }.
{
  "risk":"HIGH|MEDIUM|LOW","score":<0-100>,"confidence":<0-100>,
  "verdict":"<one line>",
  "attack_type":"<Phishing|Malware|Typosquatting|Homograph|Open Redirect|Benign>",
  "domain_analysis":"<domain analysis>",
  "explanation":"<why suspicious or safe>",
  "geo_risk":"<hosting risk>",
  "actions":["<action1>","<action2>","<action3>"]
}"""

PROMPT_SYS = """You are CyberShield AI adversarial input detector.
Return ONLY raw JSON. No markdown. Start with { end with }.
{
  "risk":"HIGH|MEDIUM|LOW","score":<0-100>,"confidence":<0-100>,
  "verdict":"<one line>",
  "injection_type":"<JAILBREAK|ROLE_OVERRIDE|INSTRUCTION_BYPASS|INDIRECT_INJECTION|CLEAN>",
  "tags":["<tag1>","<tag2>"],
  "malicious_fragment":"<injected text or NONE>",
  "technique_used":"<technique name>",
  "explanation":"<how it works, what attacker wants, why dangerous>",
  "actions":["<action1>","<action2>"]
}"""

DEEPFAKE_SYS = """You are CyberShield AI synthetic content detector.
Return ONLY raw JSON. No markdown. Start with { end with }.
{
  "risk":"HIGH|MEDIUM|LOW","score":<0-100>,"confidence":<0-100>,
  "verdict":"<one line>","synthetic_probability":<0-100>,
  "content_type":"<AI_GENERATED|HUMAN_IMPERSONATION|HYBRID|AUTHENTIC>",
  "signals":[
    {"label":"Repetitive Phrasing","value":<0-100>,"color":"red|orange|green"},
    {"label":"Unnatural Formality","value":<0-100>,"color":"red|orange|green"},
    {"label":"Lexical Diversity","value":<0-100>,"color":"red|orange|green"},
    {"label":"Human Imperfections","value":<0-100>,"color":"red|orange|green"},
    {"label":"Temporal Consistency","value":<0-100>,"color":"red|orange|green"},
    {"label":"Social Engineering Pattern","value":<0-100>,"color":"red|orange|green"}
  ],
  "explanation":"<specific language patterns>",
  "actions":["<action1>","<action2>"]
}"""

BEHAVIOR_SYS = """You are CyberShield AI UEBA engine.
Return ONLY raw JSON. No markdown. Start with { end with }.
{
  "risk":"HIGH|MEDIUM|LOW","score":<0-100>,"confidence":<0-100>,
  "verdict":"<one line>",
  "anomaly_type":"<IMPOSSIBLE_TRAVEL|BRUTE_FORCE|OFF_HOURS_ACCESS|CREDENTIAL_STUFFING|GEO_ANOMALY|SUSPICIOUS_IP|NORMAL>",
  "metrics":[
    {"label":"Location Risk","value":<0-100>,"status":"normal|warning|danger"},
    {"label":"Time Anomaly","value":<0-100>,"status":"normal|warning|danger"},
    {"label":"Failed Attempts Risk","value":<0-100>,"status":"normal|warning|danger"},
    {"label":"IP Reputation","value":<0-100>,"status":"normal|warning|danger"},
    {"label":"Behavioral Baseline Deviation","value":<0-100>,"status":"normal|warning|danger"}
  ],
  "explanation":"<why anomalous — reference location, time, IP, failures>",
  "actions":["<action1>","<action2>","<action3>"]
}"""


# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════

@app.route("/")
def serve_index():
    return send_from_directory("templates", "index.html")

@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)

@app.route("/api/health")
def health():
    return jsonify({"status":"ok","time":datetime.now().isoformat(),
                    "supported_keys":["gsk_... (Groq FREE)","sk-ant-... (Anthropic)"]})

@app.route("/api/detect-provider", methods=["POST"])
def detect_prov():
    data = request.get_json() or {}
    key  = data.get("api_key","")
    try:
        p = detect_provider(key)
        return jsonify({"provider":p,"model":GROQ_MODEL if p=="groq" else ANTHROPIC_MODEL})
    except ValueError as e:
        return jsonify({"error":str(e)}),400

@app.route("/api/scan/email", methods=["POST"])
def scan_email():
    data=request.get_json() or {}
    text=data.get("text","").strip(); api_key=get_api_key(data)
    if not text:    return jsonify({"error":"No email content"}),400
    if not api_key: return jsonify({"error":"No API key provided"}),401
    h = analyze_email_heuristics(text)
    try:
        res = call_ai(EMAIL_SYS, f"EMAIL:\n{text}\n\nPRE-ANALYSIS:\n{json.dumps(h,indent=2)}", api_key)
        ex  = [i["label"].lower()[:20] for i in res.get("indicators",[])]
        for s in h["signals"]:
            if not any(s["label"].lower()[:20] in e for e in ex):
                res.setdefault("indicators",[]).insert(0,s)
        res["_provider"]=detect_provider(api_key)
        return jsonify(res)
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/scan/url", methods=["POST"])
def scan_url():
    data=request.get_json() or {}
    url=data.get("url","").strip(); api_key=get_api_key(data)
    if not url:     return jsonify({"error":"No URL provided"}),400
    if not api_key: return jsonify({"error":"No API key provided"}),401
    local=analyze_url_locally(url)
    try:
        res=call_ai(URL_SYS,
            f"URL:{url}\nEntropy:{local['entropy']} Len:{local['length']} Domain:{local['domain']}\n"
            f"Flags:{json.dumps(local['flags'],indent=2)}", api_key)
        res["local_flags"]=local["flags"]; res["entropy"]=local["entropy"]
        res["_provider"]=detect_provider(api_key)
        return jsonify(res)
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/scan/prompt", methods=["POST"])
def scan_prompt():
    data=request.get_json() or {}
    text=data.get("text","").strip(); api_key=get_api_key(data)
    if not text:    return jsonify({"error":"No text provided"}),400
    if not api_key: return jsonify({"error":"No API key provided"}),401
    local=analyze_prompt_locally(text)
    try:
        res=call_ai(PROMPT_SYS,f"INPUT:\n{text}\n\nLOCAL MATCH:\n{json.dumps(local,indent=2)}",api_key)
        res["_provider"]=detect_provider(api_key); return jsonify(res)
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/scan/deepfake", methods=["POST"])
def scan_deepfake():
    data=request.get_json() or {}
    text=data.get("text","").strip(); api_key=get_api_key(data)
    if not text:    return jsonify({"error":"No text provided"}),400
    if not api_key: return jsonify({"error":"No API key provided"}),401
    words=text.split(); wc=len(words)
    stats={"word_count":wc,
           "avg_word_length":round(sum(len(w) for w in words)/max(wc,1),2),
           "lexical_diversity":round(len(set(text.lower().split()))/max(wc,1),3),
           "sentence_count":len(re.split(r'[.!?]+',text)),
           "has_contractions":bool(re.search(r"\b(don't|can't|won't|I'm|it's)\b",text)),
           "has_colloquials":bool(re.search(r"\b(lol|btw|tbh|gonna|wanna|ngl|yeah)\b",text,re.I))}
    try:
        res=call_ai(DEEPFAKE_SYS,f"TEXT:\n{text}\n\nSTATS:\n{json.dumps(stats,indent=2)}",api_key)
        res["_provider"]=detect_provider(api_key); return jsonify(res)
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/scan/behavior", methods=["POST"])
def scan_behavior():
    data=request.get_json() or {}
    event=data.get("event",{}); api_key=get_api_key(data)
    if not event:   return jsonify({"error":"No event data"}),400
    if not api_key: return jsonify({"error":"No API key provided"}),401
    flags=[]
    fn=re.search(r"\d+",str(event.get("failed_attempts","0")))
    fn_num=int(fn.group()) if fn else 0
    if fn_num>=10:  flags.append("HIGH_FAIL_COUNT: Brute force")
    elif fn_num>=3: flags.append("ELEVATED_FAIL_COUNT: Multiple failures")
    loc,usual=event.get("location","").lower(),event.get("usual_location","").lower()
    if loc and usual and loc.split(",")[-1].strip()!=usual.split(",")[-1].strip():
        flags.append(f"GEO_ANOMALY: {loc} vs {usual}")
    hm=re.search(r"(\d{1,2}):\d{2}\s*(AM|PM)?",event.get("login_time",""),re.I)
    if hm:
        h,ap=int(hm.group(1)),(hm.group(2) or "").upper()
        if (ap=="AM" and 1<=h<=5) or (not ap and h<6):
            flags.append(f"OFF_HOURS: {event.get('login_time','')}")
    for pat in ["203.0.113","45.89","185.220","tor","proxy"]:
        if pat in event.get("ip_address",""):
            flags.append(f"SUSPICIOUS_IP: {event['ip_address']}")
    try:
        res=call_ai(BEHAVIOR_SYS,
            f"EVENT:\n{json.dumps(event,indent=2)}\nFLAGS:\n{chr(10).join(flags) or 'None'}",
            api_key)
        res["local_flags"]=flags; res["_provider"]=detect_provider(api_key)
        return jsonify(res)
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/chat", methods=["POST"])
def ai_chat():
    data=request.get_json() or {}
    q=data.get("question","").strip(); api_key=get_api_key(data)
    if not q:       return jsonify({"error":"No question"}),400
    if not api_key: return jsonify({"error":"No API key"}),401
    sys_p="You are CyberShield AI security expert. Answer in plain text (NOT JSON), under 150 words."
    try:
        res=call_ai(sys_p,f"Context:{data.get('context','')}\nQ:{q}",api_key)
        ans=res.get("explanation") or res.get("answer") or res.get("verdict") or str(res)
        return jsonify({"answer":ans,"_provider":detect_provider(api_key)})
    except Exception as e: return jsonify({"error":str(e)}),500


if __name__=="__main__":
    print("\n"+"="*55)
    print("  CyberShield AI — Multi-Provider Backend")
    print("  URL  : http://localhost:5000")
    print()
    print("  gsk_...    → Groq  (FREE) console.groq.com")
    print("  sk-ant-... → Anthropic   console.anthropic.com")
    print()
    print("  Paste your key in the frontend header → Save")
    print("="*55+"\n")
    app.run(debug=True, port=5000, host="0.0.0.0")