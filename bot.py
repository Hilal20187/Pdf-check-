"""
LEX PDF FORENSIC PRO - Enhanced Edition
Detects PDF forgery through multi-layer forensic analysis.
"""

import os
import re
import hashlib
import tempfile
import mimetypes
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
    ConversationHandler,
)

from pypdf import PdfReader
from pypdf.errors import PdfReadError

# ============================================================
# CONFIGURATION
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
TIME_TOLERANCE_SECONDS = 300  # 5 minutes
MAX_FINDINGS_DISPLAY = 10
MAX_DAILY_FILES_PER_USER = 20

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ForensicFinding:
    severity: str  # "critical", "warning", "info"
    category: str  # "metadata", "structure", "chronology", "security", "content"
    message: str

@dataclass
class ForensicReport:
    result: str
    summary: str
    findings: List[ForensicFinding] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    file_info: Dict[str, Any] = field(default_factory=dict)
    structure: Dict[str, Any] = field(default_factory=dict)
    chronology: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, severity: str, category: str, message: str):
        self.findings.append(ForensicFinding(severity, category, message))
    
    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")
    
    def get_warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    def __init__(self, max_daily: int = MAX_DAILY_FILES_PER_USER):
        self.max_daily = max_daily
        self._users: Dict[int, List[datetime]] = {}
    
    def is_allowed(self, user_id: int) -> bool:
        now = datetime.now(timezone.utc)
        today = now.date()
        
        if user_id not in self._users:
            self._users[user_id] = []
        
        # Clean old entries
        self._users[user_id] = [
            t for t in self._users[user_id] 
            if t.date() == today
        ]
        
        return len(self._users[user_id]) < self.max_daily
    
    def record(self, user_id: int):
        self._users[user_id].append(datetime.now(timezone.utc))

rate_limiter = RateLimiter()


# ============================================================
# HASH UTILITIES
# ============================================================

def calculate_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================
# PDF METADATA EXTRACTION
# ============================================================

def get_pdf_metadata(file_path: str) -> Dict[str, str]:
    metadata = {}
    try:
        reader = PdfReader(file_path)
        if reader.metadata:
            for key, value in reader.metadata.items():
                if value is not None:
                    metadata[str(key)] = str(value)
    except Exception as e:
        logger.warning(f"Metadata extraction failed: {e}")
    return metadata


# ============================================================
# IMPROVED DATE PARSER (with timezone support)
# ============================================================

def parse_pdf_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    
    value = str(value).strip()
    
    # Pattern: D:20260809105416+01'00' or D:20260809105416Z
    match = re.search(
        r"D:(\d{4})(\d{2})(\d{2})"
        r"(\d{2})(\d{2})(\d{2})"
        r"(?:(Z)|([+-]\d{2})'(\d{2})')?",
        value
    )
    
    if not match:
        return None
    
    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    
    try:
        dt = datetime(year, month, day, hour, minute, second)
        
        # Handle timezone
        if match.group(7) == 'Z':
            dt = dt.replace(tzinfo=timezone.utc)
        elif match.group(8):
            tz_hours = int(match.group(8))
            tz_minutes = int(match.group(9))
            tz_offset = timedelta(hours=tz_hours, minutes=tz_minutes)
            dt = dt.replace(tzinfo=timezone(tz_offset))
        
        return dt
    except ValueError:
        return None


# ============================================================
# TRANSACTION DATE EXTRACTION (Improved)
# ============================================================

def extract_transaction_dates(file_path: str) -> List[Dict[str, Any]]:
    dates = []
    
    try:
        reader = PdfReader(file_path)
        text = ""
        
        for page in reader.pages:
            try:
                page_text = page.extract_text()
                if page_text:
                    text += "\n" + page_text
            except Exception:
                pass
        
        # Patterns for transaction dates
        patterns = [
            # Labeled dates
            r"(?i)(?:date\s*(?:de\s*)?(?:transaction|operation|payment)?"
            r"|transaction\s*date|date\s*of\s*transaction)"
            r"\s*[:\\-]?\s*"
            r"(\d{1,2}[./\\-]\d{1,2}[./\\-]\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?)",
            
            # Generic date with time
            r"\b(\d{1,2}[./\\-]\d{1,2}[./\\-]\d{4}\s+\d{1,2}:\d{2}(?::\d{2})?)\b",
        ]
        
        matches = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            if matches:
                break
        
        formats = [
            "%d.%m.%Y %H:%M:%S",
            "%d.%m.%Y %H:%M",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%d-%m-%Y %H:%M:%S",
            "%d-%m-%Y %H:%M",
        ]
        
        for value in matches:
            value = value.strip()
            for fmt in formats:
                try:
                    parsed = datetime.strptime(value, fmt)
                    dates.append({"raw": value, "datetime": parsed})
                    break
                except ValueError:
                    continue
                    
    except Exception as e:
        logger.warning(f"Transaction date extraction failed: {e}")
    
    return dates


# ============================================================
# RAW PDF DATA EXTRACTION
# ============================================================

def read_pdf_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()


def extract_raw_dates(data: bytes) -> Dict[str, Any]:
    creation_dates = re.findall(rb"/CreationDate\s*\((.*?)\)", data, re.DOTALL)
    modification_dates = re.findall(rb"/ModDate\s*\((.*?)\)", data, re.DOTALL)
    
    creation = None
    modification = None
    
    if creation_dates:
        creation = creation_dates[-1].decode("latin-1", errors="ignore")
    if modification_dates:
        modification = modification_dates[-1].decode("latin-1", errors="ignore")
    
    return {
        "creation_raw": creation,
        "modification_raw": modification,
        "creation_count": len(creation_dates),
        "modification_count": len(modification_dates),
    }


# ============================================================
# STRUCTURAL FORENSICS (Enhanced)
# ============================================================

def analyze_structure(data: bytes) -> Dict[str, Any]:
    findings = []
    
    # PDF Header
    if not data.startswith(b"%PDF-"):
        findings.append(("critical", "structure", "Invalid PDF header - possible fake extension"))
    
    # Version check
    version_match = re.match(rb"%PDF-(\d+\.\d+)", data[:8])
    pdf_version = version_match.group(1).decode() if version_match else "unknown"
    
    # Multiple startxref
    startxref_count = len(re.findall(rb"\bstartxref\b", data))
    if startxref_count > 1:
        findings.append(("warning", "structure", f"Multiple startxref sections ({startxref_count}) - possible incremental update"))
    
    # Previous revisions
    prev_count = len(re.findall(rb"/Prev\b", data))
    if prev_count > 0:
        findings.append(("warning", "structure", f"Previous revision references found ({prev_count})"))
    
    # Multiple EOF
    eof_count = len(re.findall(rb"%%EOF", data))
    if eof_count > 1:
        findings.append(("warning", "structure", f"Multiple EOF markers ({eof_count})"))
    
    # Object count
    object_count = len(re.findall(rb"(?m)^\d+\s+\d+\s+obj\b", data))
    
    # Producer & Creator
    producer = None
    creator = None
    
    producer_matches = re.findall(rb"/Producer\s*\((.*?)\)", data, re.DOTALL)
    if producer_matches:
        producer = producer_matches[-1].decode("latin-1", errors="ignore")
    
    creator_matches = re.findall(rb"/Creator\s*\((.*?)\)", data, re.DOTALL)
    if creator_matches:
        creator = creator_matches[-1].decode("latin-1", errors="ignore")
    
    # Suspicious producers
    suspicious_producers = ["Photoshop", "GIMP", "Paint", "online", "editor", "fake"]
    if producer:
        prod_lower = producer.lower()
        for susp in suspicious_producers:
            if susp in prod_lower:
                findings.append(("warning", "metadata", f"Suspicious producer: {producer}"))
                break
    
    # Digital signature
    has_signature = b"/ByteRange" in data or b"/FT /Sig" in data or b"/Type /Sig" in data
    
    # XMP metadata
    has_xmp = b"<x:xmpmeta" in data or b"<rdf:RDF" in data
    
    # JavaScript detection (CRITICAL)
    has_javascript = (
        b"/JavaScript" in data or 
        b"/JS" in data or
        b"/OpenAction" in data
    )
    if has_javascript:
        findings.append(("critical", "security", "JavaScript detected in PDF - potential malware"))
    
    # Embedded files
    has_embedded = b"/EmbeddedFiles" in data or b"/Names" in data
    if has_embedded:
        findings.append(("warning", "security", "Embedded files detected"))
    
    # Launch actions
    has_launch = b"/Launch" in data
    if has_launch:
        findings.append(("critical", "security", "Launch action detected - potential malware"))
    
    # URI detection
    uri_matches = re.findall(rb"/URI\s*\((.*?)\)", data)
    urls = [m.decode("latin-1", errors="ignore") for m in uri_matches]
    
    # Suspicious URLs
    suspicious_domains = ["bit.ly", "tinyurl", "t.me", "telegram", "phishing"]
    for url in urls:
        url_lower = url.lower()
        for domain in suspicious_domains:
            if domain in url_lower:
                findings.append(("critical", "security", f"Suspicious URL detected: {url[:100]}"))
                break
    
    return {
        "findings": findings,
        "pdf_version": pdf_version,
        "startxref_count": startxref_count,
        "prev_count": prev_count,
        "eof_count": eof_count,
        "object_count": object_count,
        "producer": producer,
        "creator": creator,
        "has_signature": has_signature,
        "has_xmp": has_xmp,
        "has_javascript": has_javascript,
        "has_embedded": has_embedded,
        "urls": urls[:5],  # Limit to 5
    }


# ============================================================
# CHRONOLOGY FORENSICS (Enhanced)
# ============================================================

def check_chronology(
    file_path: str,
    raw_dates: Dict[str, Any],
    report: ForensicReport
) -> Dict[str, Any]:
    
    transaction_dates = extract_transaction_dates(file_path)
    creation = parse_pdf_date(raw_dates["creation_raw"])
    modification = parse_pdf_date(raw_dates["modification_raw"])
    now = datetime.now(timezone.utc)
    
    # Check future dates
    if creation and creation > now + timedelta(seconds=TIME_TOLERANCE_SECONDS):
        report.add_finding("critical", "chronology", 
            f"Creation date is in the FUTURE: {creation.isoformat()}")
    
    if modification and modification > now + timedelta(seconds=TIME_TOLERANCE_SECONDS):
        report.add_finding("critical", "chronology", 
            f"Modification date is in the FUTURE: {modification.isoformat()}")
    
    # Check creation vs modification consistency
    if creation and modification:
        if creation > modification + timedelta(seconds=TIME_TOLERANCE_SECONDS):
            report.add_finding("critical", "chronology", 
                "Creation date is AFTER modification date (impossible)")
        
        if creation != modification:
            report.add_finding("info", "chronology", 
                "File has been modified after creation")
    
    # Check transaction vs PDF dates
    for tx in transaction_dates:
        tx_date = tx["datetime"]
        
        if creation:
            diff = (tx_date - creation.replace(tzinfo=None)).total_seconds()
            if diff > TIME_TOLERANCE_SECONDS:
                days = diff / 86400
                if days >= 1:
                    report.add_finding("critical", "chronology",
                        f"PDF created {days:.1f} days BEFORE transaction")
                else:
                    hours = diff / 3600
                    report.add_finding("warning", "chronology",
                        f"PDF created {hours:.1f} hours BEFORE transaction")
        
        if modification:
            diff = (tx_date - modification.replace(tzinfo=None)).total_seconds()
            if diff > TIME_TOLERANCE_SECONDS:
                days = diff / 86400
                if days >= 1:
                    report.add_finding("critical", "chronology",
                        f"PDF modified {days:.1f} days BEFORE transaction")
                else:
                    hours = diff / 3600
                    report.add_finding("warning", "chronology",
                        f"PDF modified {hours:.1f} hours BEFORE transaction")
    
    return {
        "transaction_dates": transaction_dates,
        "creation": creation.isoformat() if creation else None,
        "modification": modification.isoformat() if modification else None,
    }


# ============================================================
# SIGNATURE FORENSICS
# ============================================================

def analyze_signatures(file_path: str, report: ForensicReport) -> Dict[str, Any]:
    sig_info = {"has_signature": False, "signatures": []}
    
    try:
        reader = PdfReader(file_path)
        
        if "/AcroForm" in reader.trailer["/Root"]:
            acroform = reader.trailer["/Root"]["/AcroForm"]
            if "/Fields" in acroform:
                for field in acroform["/Fields"]:
                    field_obj = field.get_object()
                    if field_obj.get("/FT") == "/Sig":
                        sig_info["has_signature"] = True
                        sig_dict = {
                            "name": str(field_obj.get("/T", "Unknown")),
                            "reason": str(field_obj.get("/V", {}).get("/Reason", "N/A")) if field_obj.get("/V") else "N/A",
                            "location": str(field_obj.get("/V", {}).get("/Location", "N/A")) if field_obj.get("/V") else "N/A",
                        }
                        sig_info["signatures"].append(sig_dict)
                        
                        report.add_finding("info", "security", 
                            f"Digital signature found: {sig_dict['name']}")
    except Exception as e:
        logger.warning(f"Signature analysis failed: {e}")
    
    return sig_info


# ============================================================
# CONTENT FORENSICS
# ============================================================

def analyze_content(file_path: str, report: ForensicReport) -> Dict[str, Any]:
    content_info = {"page_count": 0, "images": [], "fonts": []}
    
    try:
        reader = PdfReader(file_path)
        content_info["page_count"] = len(reader.pages)
        
        # Check for empty pages
        empty_pages = 0
        for i, page in enumerate(reader.pages):
            text = page.extract_text() or ""
            if len(text.strip()) < 10:
                empty_pages += 1
        
        if empty_pages > 0:
            report.add_finding("warning", "content", 
                f"{empty_pages} near-empty pages detected")
        
        # Check page count anomalies
        if content_info["page_count"] > 50:
            report.add_finding("info", "content", 
                f"Large document: {content_info['page_count']} pages")
        
    except Exception as e:
        logger.warning(f"Content analysis failed: {e}")
    
    return content_info


# ============================================================
# MAIN FORENSIC ENGINE
# ============================================================

def forensic_analysis(file_path: str) -> ForensicReport:
    report = ForensicReport(
        result="🟢 لم يتم اكتشاف أي تعديل مشبوه",
        summary="لا توجد شبهة في التعديل"
    )
    
    data = read_pdf_bytes(file_path)
    metadata = get_pdf_metadata(file_path)
    raw_dates = extract_raw_dates(data)
    
    report.metadata = metadata
    
    # Structure analysis
    structure = analyze_structure(data)
    for severity, category, message in structure["findings"]:
        report.add_finding(severity, category, message)
    
    report.structure = {
        k: v for k, v in structure.items() 
        if k != "findings"
    }
    
    # Duplicate dates
    if raw_dates["creation_count"] > 1:
        report.add_finding("warning", "metadata", 
            f"Multiple CreationDate entries ({raw_dates['creation_count']})")
    
    if raw_dates["modification_count"] > 1:
        report.add_finding("warning", "metadata", 
            f"Multiple ModDate entries ({raw_dates['modification_count']})")
    
    # Creation vs Modification
    creation = parse_pdf_date(raw_dates["creation_raw"])
    modification = parse_pdf_date(raw_dates["modification_raw"])
    
    if creation and modification and creation != modification:
        report.add_finding("info", "metadata", 
            "CreationDate differs from ModDate")
    
    # Chronology
    chronology = check_chronology(file_path, raw_dates, report)
    report.chronology = chronology
    
    # Signatures
    sig_info = analyze_signatures(file_path, report)
    report.security["signatures"] = sig_info
    
    # Content
    content_info = analyze_content(file_path, report)
    report.file_info["content"] = content_info
    
    # Final result
    critical_count = report.get_critical_count()
    warning_count = report.get_warning_count()
    
    if critical_count > 0:
        report.result = "🔴 تم اكتشاف شبهة تزوير خطيرة"
        report.summary = f"تم العثور على {critical_count} مشكلة حرجة و {warning_count} تحذير"
    elif warning_count > 0:
        report.result = "🟡 تم اكتشاف بعض الشبهات"
        report.summary = f"تم العثور على {warning_count} تحذير"
    
    return report


# ============================================================
# FORMAT REPORT FOR TELEGRAM
# ============================================================

def format_report(
    filename: str,
    file_size: int,
    mime_type: str,
    file_hash: str,
    report: ForensicReport
) -> str:
    
    # Severity emojis
    severity_icons = {
        "critical": "🔴",
        "warning": "🟡",
        "info": "🔵"
    }
    
    # Build findings text
    findings_text = ""
    for finding in report.findings[:MAX_FINDINGS_DISPLAY]:
        icon = severity_icons.get(finding.severity, "⚪")
        findings_text += f"{icon} [{finding.category.upper()}] {finding.message}\n"
    
    if len(report.findings) > MAX_FINDINGS_DISPLAY:
        findings_text += f"\n... و {len(report.findings) - MAX_FINDINGS_DISPLAY} نتائج أخرى"
    
    if not findings_text:
        findings_text = "✅ لا توجد ملاحظات"
    
    # Structure info
    struct = report.structure
    struct_text = (
        f"• الإصدار: {struct.get('pdf_version', 'N/A')}\n"
        f"• الكائنات: {struct.get('object_count', 'N/A')}\n"
        f"• توقيع رقمي: {'نعم' if struct.get('has_signature') else 'لا'}\n"
        f"• XMP: {'نعم' if struct.get('has_xmp') else 'لا'}\n"
        f"• JavaScript: {'⚠️ نعم' if struct.get('has_javascript') else 'لا'}\n"
        f"• ملفات مضمنة: {'⚠️ نعم' if struct.get('has_embedded') else 'لا'}"
    )
    
    # Metadata
    meta_text = ""
    if report.metadata:
        for key, value in list(report.metadata.items())[:5]:
            meta_text += f"• {key}: {value[:50]}\n"
    else:
        meta_text = "لا توجد بيانات وصفية"
    
    message = (
        f"🔎 <b>LEX PDF FORENSIC PRO</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n\n"
        
        f"📄 <b>الملف:</b> <code>{filename}</code>\n"
        f"📦 <b>الحجم:</b> {file_size:,} بايت\n"
        f"🧬 <b>MIME:</b> {mime_type}\n"
        f"📑 <b>الصفحات:</b> {report.file_info.get('content', {}).get('page_count', 'N/A')}\n\n"
        
        f"🔐 <b>SHA-256:</b>\n"
        f"<code>{file_hash}</code>\n\n"
        
        f"📊 <b>النتيجة:</b>\n"
        f"{report.result}\n\n"
        
        f"⚠️ <b>الملخص:</b>\n"
        f"{report.summary}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔍 <b>التحليل البنيوي:</b>\n"
        f"{struct_text}\n\n"
        
        f"📝 <b>البيانات الوصفية:</b>\n"
        f"{meta_text}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📋 <b>النتائج التفصيلية:</b>\n"
        f"{findings_text}\n\n"
        
        f"━━━━━━━━━━━━━━━━━━\n"
        f"<i>By LEX Forensics</i>"
    )
    
    return message


# ============================================================
# TELEGRAM HANDLERS
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔎 <b>LEX PDF FORENSIC PRO</b>\n\n"
        "أرسل ملف PDF لتحليله جنائيًا وكشف التزوير.\n\n"
        "<b>القدرات:</b>\n"
        "• كشف التواريخ المستقبلية\n"
        "• كشف JavaScript المخفي\n"
        "• كشف التوقيعات الرقمية\n"
        "• تحليل البنية الداخلية\n"
        "• فحص الروابط المشبوهة\n\n"
        "⚠️ ملاحظة: الحد الأقصى 50 ميجابايت",
        parse_mode="HTML"
    )


async def handle_pdf(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    
    if not document:
        return
    
    user_id = update.effective_user.id
    
    # Rate limit check
    if not rate_limiter.is_allowed(user_id):
        await update.message.reply_text(
            "⏳ لقد تجاوزت الحد اليومي (20 ملف).\n"
            "يرجى المحاولة غدًا."
        )
        return
    
    # Size check
    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            "❌ الملف كبير جدًا.\n"
            "الحد الأقصى: 50 ميجابايت."
        )
        return
    
    # Extension check
    filename = document.file_name or "document.pdf"
    if not filename.lower().endswith(".pdf"):
        await update.message.reply_text("❌ يرجى إرسال ملف PDF فقط.")
        return
    
    processing = await update.message.reply_text("🔎 جاري تحليل الملف...")
    temp_path = None
    
    try:
        # Download
        telegram_file = await document.get_file()
        
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            temp_path = tmp.name
        
        await telegram_file.download_to_drive(temp_path)
        rate_limiter.record(user_id)
        
        # Validate PDF header
        with open(temp_path, "rb") as f:
            header = f.read(5)
        
        if header != b"%PDF-":
            await processing.edit_text("❌ ملف PDF غير صالح.")
            return
        
        # MIME
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = "application/pdf"
        
        # Hash
        file_hash = calculate_sha256(temp_path)
        
        # Forensic analysis
        report = forensic_analysis(temp_path)
        
        # File size
        file_size = document.file_size or os.path.getsize(temp_path)
        
        # Format and send
        message = format_report(filename, file_size, mime_type, file_hash, report)
        
        await processing.edit_text(message, parse_mode="HTML")
        
        # Log for debugging
        logger.info(f"Analysis complete for user {user_id}: {filename}")
        
    except PdfReadError as e:
        logger.error(f"PDF read error: {e}")
        await processing.edit_text(
            "❌ فشل قراءة ملف PDF.\n"
            "قد يكون الملف تالفًا أو محميًا بكلمة مرور."
        )
    except Exception as error:
        logger.error(f"Analysis error: {repr(error)}", exc_info=True)
        try:
            await processing.edit_text(
                "❌ فشل التحليل.\n\n"
                f"Error: {str(error)[:500]}"
            )
        except Exception:
            pass
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Bot error: {repr(context.error)}", exc_info=True)


# ============================================================
# MAIN
# ============================================================

def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is missing.")
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.PDF, handle_pdf))
    application.add_error_handler(error_handler)
    
    logger.info("LEX PDF FORENSIC PRO started.")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
