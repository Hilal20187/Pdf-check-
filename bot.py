import os
import re
import hashlib
import logging
import tempfile
from datetime import datetime, timezone

import fitz  # PyMuPDF
from telegram import Update
from telegram.ext import (
    Application,
    MessageHandler,
    ContextTypes,
    filters,
)

# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing")

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger("LEX")

# ============================================================
# CONSTANTS
# ============================================================

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

# PDF modification indicators
MODIFICATION_KEYWORDS = [
    "/ModDate",
    "/ModDate",
    "/Producer",
    "/Creator",
]

EDITORS = [
    "adobe acrobat",
    "acrobat",
    "foxit",
    "nitro",
    "pdfelement",
    "pdf-xchange",
    "smallpdf",
    "ilovepdf",
    "sejda",
    "canva",
    "photoshop",
    "gimp",
    "libreoffice draw",
    "inkscape",
    "microsoft word",
]

ORIGINAL_PRODUCERS = [
    "bary",
    "pdfium",
    "itext",
    "itextsharp",
    "reportlab",
    "wkhtmltopdf",
    "qt",
    "microsoft",
    "apple",
    "google",
]

# ============================================================
# HELPERS
# ============================================================

def normalize(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    return str(value)


def lower(value):
    return normalize(value).lower()


def parse_pdf_date(value):
    """
    PDF date:
    D:YYYYMMDDHHmmSSOHH'mm'
    """

    value = normalize(value).strip()

    if not value:
        return None

    if value.startswith("D:"):
        value = value[2:]

    match = re.match(
        r"(\d{4})"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?",
        value,
    )

    if not match:
        return None

    year = int(match.group(1))
    month = int(match.group(2) or 1)
    day = int(match.group(3) or 1)
    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    second = int(match.group(6) or 0)

    try:
        return datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except Exception:
        return None


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)

            if not block:
                break

            h.update(block)

    return h.hexdigest()


# ============================================================
# RAW PDF ANALYSIS
# ============================================================

def raw_pdf_analysis(path):
    result = {
        "valid_header": False,
        "eof": False,
        "xref": 0,
        "startxref": 0,
        "incremental": False,
        "obj_count": 0,
        "stream_count": 0,
        "metadata_moddate": False,
        "raw_moddate": False,
        "suspicious_keywords": 0,
        "errors": 0,
    }

    try:
        with open(path, "rb") as f:
            data = f.read()

        if not data:
            result["errors"] += 1
            return result

        # PDF header
        result["valid_header"] = data.startswith(b"%PDF-")

        # EOF
        result["eof"] = b"%%EOF" in data[-4096:]

        # xref
        result["xref"] = len(
            re.findall(rb"(?m)^xref\s*$", data)
        )

        # startxref
        result["startxref"] = len(
            re.findall(rb"startxref", data)
        )

        # objects
        result["obj_count"] = len(
            re.findall(rb"(?m)^\s*\d+\s+\d+\s+obj\b", data)
        )

        # streams
        result["stream_count"] = len(
            re.findall(rb"\bstream\r?\n", data)
        )

        # ModDate inside raw PDF
        result["raw_moddate"] = (
            b"/ModDate" in data
            or b"/MODDATE" in data
            or b"/moddate" in data
        )

        # incremental updates
        prev_count = len(
            re.findall(rb"/Prev\s+\d+", data)
        )

        result["incremental"] = prev_count > 0

        # suspicious editing software
        text = data.decode(
            "latin-1",
            errors="ignore"
        ).lower()

        for item in EDITORS:
            if item in text:
                result["suspicious_keywords"] += 1

        return result

    except Exception:
        result["errors"] += 1
        return result


# ============================================================
# PDF STRUCTURE ANALYSIS
# ============================================================

def inspect_pdf(path):
    score = 0

    reasons = []

    raw = raw_pdf_analysis(path)

    # --------------------------------------------------------
    # BASIC STRUCTURE
    # --------------------------------------------------------

    if not raw["valid_header"]:
        score += 100
        reasons.append("invalid_header")

    if not raw["eof"]:
        score += 35
        reasons.append("missing_eof")

    if raw["obj_count"] == 0:
        score += 50
        reasons.append("no_objects")

    if raw["incremental"]:
        score += 20
        reasons.append("incremental_update")

    # --------------------------------------------------------
    # OPEN PDF
    # --------------------------------------------------------

    try:
        doc = fitz.open(path)
    except Exception:
        return {
            "verdict": "SUSPICIOUS",
            "score": 100,
        }

    try:
        if doc.page_count == 0:
            score += 50
            reasons.append("zero_pages")

        # ----------------------------------------------------
        # METADATA
        # ----------------------------------------------------

        metadata = doc.metadata or {}

        creation_date = metadata.get("creationDate", "")
        modification_date = metadata.get("modDate", "")

        creation_dt = parse_pdf_date(creation_date)
        modification_dt = parse_pdf_date(modification_date)

        if modification_date:
            score += 8

        if modification_dt and creation_dt:
            if modification_dt > creation_dt:
                # A modified PDF is not automatically fake.
                # Small penalty only.
                score += 5

        # ----------------------------------------------------
        # PRODUCER / CREATOR
        # ----------------------------------------------------

        producer = lower(metadata.get("producer", ""))
        creator = lower(metadata.get("creator", ""))

        combined = producer + " " + creator

        for editor in EDITORS:
            if editor in combined:
                score += 18
                reasons.append("editing_software")
                break

        # ----------------------------------------------------
        # PAGE ANALYSIS
        # ----------------------------------------------------

        page_sizes = []
        text_pages = 0
        image_pages = 0
        empty_pages = 0

        font_count = 0
        image_count = 0

        for page in doc:
            rect = page.rect

            page_sizes.append(
                (
                    round(rect.width, 2),
                    round(rect.height, 2)
                )
            )

            text = page.get_text("text").strip()

            if text:
                text_pages += 1
            else:
                empty_pages += 1

            try:
                images = page.get_images(full=True)

                if images:
                    image_pages += 1
                    image_count += len(images)

            except Exception:
                pass

            try:
                fonts = page.get_fonts(full=True)
                font_count += len(fonts)
            except Exception:
                pass

        # ----------------------------------------------------
        # MIXED CONTENT
        # ----------------------------------------------------

        if text_pages > 0 and image_pages > 0:
            # Mixed text/images is normal for many receipts.
            # Only tiny signal.
            score += 2

        # ----------------------------------------------------
        # PAGE SIZE INCONSISTENCY
        # ----------------------------------------------------

        unique_sizes = set(page_sizes)

        if len(unique_sizes) > 1 and doc.page_count > 1:
            score += 4

        # ----------------------------------------------------
        # RAW MODDATE
        # ----------------------------------------------------

        if raw["raw_moddate"]:
            score += 4

        # ----------------------------------------------------
        # SUSPICIOUS EDITOR FOUND
        # ----------------------------------------------------

        if raw["suspicious_keywords"] > 0:
            score += min(
                raw["suspicious_keywords"] * 5,
                20
            )

        # ----------------------------------------------------
        # PDF REPAIR / XREF SIGNAL
        # ----------------------------------------------------

        if raw["startxref"] == 0:
            score += 20
            reasons.append("missing_startxref")

        # ----------------------------------------------------
        # VERY SMALL PDF
        # ----------------------------------------------------

        file_size = os.path.getsize(path)

        if file_size < 1000:
            score += 30
            reasons.append("very_small_file")

        # ----------------------------------------------------
        # OBJECT / STREAM SANITY
        # ----------------------------------------------------

        if raw["obj_count"] > 0:
            if raw["stream_count"] == 0 and image_count > 0:
                score += 15
                reasons.append("stream_anomaly")

        # ----------------------------------------------------
        # METADATA CONTRADICTIONS
        # ----------------------------------------------------

        producer_has_editor = any(
            editor in producer
            for editor in EDITORS
        )

        creator_has_original = any(
            producer_name in combined
            for producer_name in ORIGINAL_PRODUCERS
        )

        if producer_has_editor and creator_has_original:
            score += 8
            reasons.append("producer_creator_mismatch")

        # ----------------------------------------------------
        # CLOSE
        # ----------------------------------------------------

        doc.close()

        # ----------------------------------------------------
        # FINAL VERDICT
        # ----------------------------------------------------

        # Important:
        # We deliberately use conservative thresholds.
        #
        # 0-24   = normal
        # 25-49  = suspicious
        # 50+    = suspicious
        #
        # This prevents a simple ModDate from declaring
        # a legitimate PDF fake.

        if score >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CORRECT"

        return {
            "verdict": verdict,
            "score": min(score, 100),
        }

    except Exception:

        try:
            doc.close()
        except Exception:
            pass

        return {
            "verdict": "SUSPICIOUS",
            "score": 100,
        }


# ============================================================
# TELEGRAM
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.effective_message

    if not message:
        return

    document = message.document

    if not document:
        return

    filename = document.file_name or "document.pdf"

    # --------------------------------------------------------
    # ONLY PDF
    # --------------------------------------------------------

    if not filename.lower().endswith(".pdf"):
        return

    # --------------------------------------------------------
    # SIZE LIMIT
    # --------------------------------------------------------

    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await message.reply_text(
            "مشبوه\n\nBy LEX"
        )
        return

    temp_path = None

    try:

        # ----------------------------------------------------
        # TEMP FILE
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False
        ) as tmp:

            temp_path = tmp.name

        # ----------------------------------------------------
        # DOWNLOAD
        # ----------------------------------------------------

        tg_file = await context.bot.get_file(
            document.file_id
        )

        await tg_file.download_to_drive(
            custom_path=temp_path
        )

        # ----------------------------------------------------
        # FORENSIC
        # ----------------------------------------------------

        result = inspect_pdf(temp_path)

        verdict = result["verdict"]

        # ----------------------------------------------------
        # USER OUTPUT
        # ----------------------------------------------------

        if verdict == "SUSPICIOUS":
            text = "مشبوه\n\nBy LEX"
        else:
            text = "صحيح\n\nBy LEX"

        await message.reply_text(text)

        logger.info(
            "LEX | %s | %s | score=%s",
            filename,
            verdict,
            result.get("score"),
        )

    except Exception as e:

        logger.exception(
            "PDF analysis error: %s",
            e
        )

        # User still gets ONLY the requested format
        await message.reply_text(
            "مشبوه\n\nBy LEX"
        )

    finally:

        if temp_path:
            try:
                os.remove(temp_path)
            except Exception:
                pass


# ============================================================
# START
# ============================================================

def main():

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    application.add_handler(
        MessageHandler(
            filters.Document.PDF,
            handle_pdf
        )
    )

    logger.info("LEX PDF FORENSIC BOT STARTED")

    application.run_polling(
        drop_pending_updates=True
    )


if __name__ == "__main__":
    main() 
