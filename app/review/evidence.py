"""Turn a corpus of documents (repo files or fetched web pages) into evidence signals for the rules table.

A signal is "was there evidence of X?" with up to 3 pointers (path/URL + line). Absence is only ever reported as
"not detected": the control may exist somewhere this scan cannot see.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

I = re.IGNORECASE
_UI_EXT = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".ejs", ".hbs", ".twig", ".jinja", ".j2", ".erb", ".php", ".blade.php"}
_CODE_EXT = {".py", ".js", ".ts", ".php", ".rb", ".java", ".go", ".cs", ".kt", ".rs"}
_TEST = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?)(/|$)", I)
_NON_APP = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|docs?|examples?|samples?|demos?|tutorials?|\.github|storybook|e2e|cypress)(/|$)", I)

TEXT_SIGNALS: dict[str, re.Pattern] = {
    "privacy_policy": re.compile(r"privacy[\s_-]*(policy|notice|statement)|/privacy\b|datenschutz|politique de confidentialit", I),
    "terms": re.compile(r"terms[\s_-]*(of|&|and)[\s_-]*(service|use|sale|conditions)|terms[\s_-]*&[\s_-]*conditions|/terms\b|/tos\b|conditions g[eé]n[eé]rales|\bagb\b", I),
    "cookie_consent": re.compile(r"cookiebot|onetrust|cookieconsent|cookie-consent|cookie_consent|osano|iubenda|termly|usercentrics|klaro|axeptio|complianz|cookieyes|didomi|quantcast|trustarc|"
                                 r"cookie[\s_-]*(banner|notice|preferences|settings|policy)|consent[\s_-]*mode|react-cookie-consent|cmp\.js", I),
    "trackers": re.compile(r"googletagmanager\.com|google-analytics\.com|gtag\(|\bga\(\s*['\"]create|fbq\(|connect\.facebook\.net|hotjar|clarity\.ms|mixpanel|"
                           r"cdn\.segment\.(com|io)|analytics\.js|snap\.licdn\.com|analytics\.tiktok\.com|doubleclick\.net|amplitude|posthog|heapanalytics|ads\.twitter|adsbygoogle", I),
    "refund_policy": re.compile(r"refund[\s_-]*polic|return[s]?[\s_-]*polic|returns?[\s_-]*(and|&)[\s_-]*refunds?|right[\s_-]*of[\s_-]*withdrawal|right[\s_-]*to[\s_-]*withdraw|money[\s_-]*back|exchange[\s_-]*polic|cancellation[\s_-]*polic|/refunds?\b|/returns?\b|widerrufsbelehrung|widerruf", I),
    "withdrawal_function": re.compile(r"withdraw(al)?[\s_-]*(from[\s_-]*)?(the[\s_-]*)?contract|withdrawal[\s_-]*(button|form|function)|widerrufsbutton|bouton de r[eé]tractation", I),
    "checkout": re.compile(r"add[\s_-]?to[\s_-]?cart|checkout|shopping[\s_-]?cart|\bbasket\b|PaymentIntent|razorpay|paypal|woocommerce|shopify", I),
    "provider_identity": re.compile(r"impressum|imprint|legal[\s_-]*notice|registered[\s_-]*(office|address)|\bVAT[\s_-]*(id|number|no)|company[\s_-]*(registration|number)|\bGSTIN\b|\bCIN\s*[:\-]|commercial[\s_-]*register|handelsregister|mentions l[eé]gales", I),
    "user_accounts": re.compile(r"django\.contrib\.auth|passport|next-?auth|devise|auth0|clerk|supabase\.auth|firebase/auth|createUserWithEmailAndPassword|password_hash|bcrypt|argon2|sign[\s_-]?up|log[\s_-]?in\b|register", I),
    "data_rights": re.compile(r"delete[\s_-]?(my[\s_-]?)?(account|user|data)|export[\s_-]?(my[\s_-]?)?data|data[\s_-]?(export|portability)|download[\s_-]?my[\s_-]?data|\bdsar\b|subject[\s_-]?access|right[\s_-]*to[\s_-]*(erasure|be[\s_-]*forgotten)|erase[\s_-]?user|anonymi[sz]e[\s_-]?user|account[\s_-]?deletion|deleteUser|delete_user|destroy_account|deleteAccount", I),
    "grievance_officer": re.compile(r"grievance[\s_-]*(officer|redress)", I),
    "do_not_sell": re.compile(r"do[\s_-]?not[\s_-]?sell|your[\s_-]?privacy[\s_-]?choices|globalprivacycontrol|opt[\s_-]?out[\s_-]*of[\s_-]*(the[\s_-]*)?(sale|sharing)", I),
    "email_sending": re.compile(r"sendgrid|mailgun|nodemailer|smtplib|postmark|mailchimp|sendinblue|brevo|django\.core\.mail|send_mail\(|sendMail\(|\bresend\.emails|boto3.{0,40}ses|@aws-sdk/client-ses", I),
    "unsubscribe": re.compile(r"unsubscribe|list-unsubscribe|email[\s_-]*preferences|opt[\s_-]?out of (marketing )?emails", I),
    "subscriptions": re.compile(r"subscriptions\.create|mode\s*[:=]\s*['\"]subscription['\"]|paddle|lemon\s?squeezy|chargebee|recurly|razorpay.{0,40}subscription|billing[\s_-]*plan|stripe.{0,60}subscription", I),
    "cancel_flow": re.compile(r"cancel[\s_-]*(my[\s_-]*)?(subscription|plan|membership)|subscriptions\.(cancel|del)|billing[\s_-]*portal|billingPortal|customer[\s_-]*portal|manage[\s_-]*subscription|cancel_at_period_end", I),
}
RAW_CARD = re.compile(r"(request|req)\.[\w.\[\]'\"]*?(card[_-]?number|cvv|cvc)|\b(card_number|cardnumber|cvv|cvc)\s*=\s*(models\.|Column|db\.|sa\.)|[\"'](card_number|cvv|cvc)[\"']\s*:", I)
# paths that evidence a signal even if the text never says it (e.g. privacy.html, /imprint)
PATH_SIGNALS = {
    "privacy_policy": re.compile(r"privacy|datenschutz", I),
    "terms": re.compile(r"(^|[/_-])(terms|tos|conditions|agb)([/_.-]|$)", I),
    "refund_policy": re.compile(r"refund|returns?([/_.-]|$)|withdrawal|widerruf", I),
    "provider_identity": re.compile(r"imprint|impressum|legal[-_]?notice", I),
    "grievance_officer": re.compile(r"grievance", I),
    "cookie_consent": re.compile(r"cookie", I),
}
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{2,40}@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
FREEMAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", "aol.com", "icloud.com", "mail.com", "yahoo.in", "rediffmail.com"}
IGNORE_EMAIL_DOMAINS = {"example.com", "example.org", "test.com", "domain.com", "email.com", "yourdomain.com", "company.com", "sentry.io", "users.noreply.github.com"}
IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".js", ".css")


@dataclass
class Doc:
    ref: str           # repo path or page URL
    kind: str          # file | page
    text: str


@dataclass
class Signals:
    found: dict[str, list[dict]] = field(default_factory=dict)
    emails: dict[str, list[str]] = field(default_factory=dict)   # domain -> addresses
    has_web_ui: bool = False
    docs: int = 0
    html_docs: int = 0

    def has(self, name: str) -> bool:
        return bool(self.found.get(name))

    def evidence(self, name: str) -> list[dict]:
        return self.found.get(name, [])[:3]


def _ext(ref: str) -> str:
    name = ref.rsplit("/", 1)[-1].lower()
    return "." + name.rsplit(".", 1)[1] if "." in name else ""


def _add(sig: Signals, name: str, ref: str, line: int | None, match: str) -> None:
    lst = sig.found.setdefault(name, [])
    if len(lst) < 3 and not any(e["ref"] == ref for e in lst):
        e = {"ref": ref, "match": match.strip()[:80]}
        if line:
            e["line"] = line
        lst.append(e)


def extract_signals(docs: list[Doc]) -> Signals:
    sig = Signals(docs=len(docs))
    imgs_total = imgs_missing = 0
    for d in docs:
        ext = _ext(d.ref)
        is_page = d.kind == "page"
        in_tests = bool(_TEST.search(d.ref)) and not is_page
        if is_page or (ext in _UI_EXT and not _NON_APP.search(d.ref)):  # templates under docs/examples/tests do not prove the app has a UI
            sig.has_web_ui = True
        text = d.text[:400_000]
        for name, rx in PATH_SIGNALS.items():
            if rx.search(d.ref):
                _add(sig, name, d.ref, None, "path")
        for ln, line in enumerate(text.splitlines(), 1):
            if len(line) > 3000:
                continue
            for name, rx in TEXT_SIGNALS.items():
                if name not in sig.found or len(sig.found[name]) < 3:
                    m = rx.search(line)
                    if m and not (in_tests and name not in ("trackers",)):
                        _add(sig, name, d.ref, ln, m.group(0))
            if ext in _CODE_EXT and not in_tests:
                m = RAW_CARD.search(line)
                if m:
                    _add(sig, "raw_card_fields", d.ref, ln, m.group(0))
            if not in_tests:
                for m in EMAIL.finditer(line):
                    dom = m.group(1).lower()
                    if dom in IGNORE_EMAIL_DOMAINS or m.group(0).lower().endswith(IMG_EXT) or "noreply" in m.group(0).lower() or "no-reply" in m.group(0).lower():
                        continue
                    sig.emails.setdefault(dom, [])
                    if m.group(0).lower() not in sig.emails[dom] and len(sig.emails[dom]) < 5:
                        sig.emails[dom].append(m.group(0).lower())
        if is_page or ext in (".html", ".htm", ".jinja", ".j2", ".ejs", ".hbs", ".twig", ".erb"):
            low = text.lower()
            if "<html" in low:
                sig.html_docs += 1
                if not re.search(r"<html[^>]*\blang\s*=", low):
                    _add(sig, "a11y_gaps", d.ref, None, "<html> without lang attribute")
            tags = re.findall(r"<img\b[^>]*>", low)
            imgs_total += len(tags)
            imgs_missing += sum(1 for t in tags if not re.search(r"\balt\s*=", t))
    if imgs_total >= 3 and imgs_missing / imgs_total >= 0.3:
        _add(sig, "a11y_gaps", "markup", None, f"{imgs_missing} of {imgs_total} images have no alt attribute")
    domains = set(sig.emails)
    if len(domains) > 1 or (domains & FREEMAIL):
        shown = [a for d in sorted(domains) for a in sig.emails[d]][:4]
        _add(sig, "mixed_contacts", "project", None, ", ".join(shown))
    return sig
