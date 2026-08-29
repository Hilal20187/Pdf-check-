import os
import re
import json
import math
import shutil
import hashlib
import logging
import tempfile
from pathlib import Path
from datetime import datetime, timezone

import fitz  # PyMuPDF

from telegram import Update
from telegram.constants import ChatAction
from telegram.error import Conflict, NetworkError, TimedOut, RetryAfter
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)


# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

# اختياري: إذا وضعته، البوت يقبل الملفات من هذا الـID فقط
ADMIN_ID = os.getenv("ADMIN_ID", "").strip()

MAX_FILE_MB = 20
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("LEX-PDF")


# ============================================================
# HELPERS
# ============================================================

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def truncate(text, length=180):
    text = str(text or "").strip()

    if len(text) <= length:
        return text

    return text[:length - 3] + "..."


def is_allowed_user(update: Update) -> bool:
    if not ADMIN_ID:
        return True

    user = update.effective_user

    if not user:
        return False

    return str(user.id) == ADMIN_ID


# ============================================================
# PDF ANALYSIS
# ============================================================

def analyze_pdf(path: Path):

    result = {
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "pages": 0,
        "metadata": {},
        "fonts": [],
        "images": 0,
        "annotations": 0,
        "javascript": False,
        "embedded_files": 0,
        "forms": False,
        "encrypted": False,
        "signed": False,
        "incremental": False,
        "suspicious": [],
        "warnings": [],
        "score": 0,
    }

    doc = None

    try:

        # ----------------------------------------------------
        # OPEN PDF
        # ----------------------------------------------------

        doc = fitz.open(path)

        result["pages"] = len(doc)

        if len(doc) == 0:
            result["suspicious"].append(
                "PDF contains no pages"
            )
            result["score"] += 30

        # ----------------------------------------------------
        # ENCRYPTION
        # ----------------------------------------------------

        try:
            result["encrypted"] = bool(doc.is_encrypted)
        except Exception:
            pass

        if result["encrypted"]:
            result["warnings"].append(
                "الملف مشفّر أو محمي بكلمة مرور."
            )

        # ----------------------------------------------------
        # METADATA
        # ----------------------------------------------------

        metadata = doc.metadata or {}

        result["metadata"] = {
            "format": metadata.get("format"),
            "title": metadata.get("title"),
            "author": metadata.get("author"),
            "subject": metadata.get("subject"),
            "keywords": metadata.get("keywords"),
            "creator": metadata.get("creator"),
            "producer": metadata.get("producer"),
            "creationDate": metadata.get("creationDate"),
            "modDate": metadata.get("modDate"),
        }

        creator = str(
            metadata.get("creator") or ""
        ).lower()

        producer = str(
            metadata.get("producer") or ""
        ).lower()

        # برامج التحرير الشائعة ليست دليل تزوير وحدها
        editing_programs = [
            "photoshop",
            "gimp",
            "illustrator",
            "indesign",
            "acrobat",
            "foxit",
            "nitro",
            "libreoffice",
            "word",
            "canva",
        ]

        found_editors = []

        combined = creator + " " + producer

        for program in editing_programs:
            if program in combined:
                found_editors.append(program)

        if found_editors:
            result["warnings"].append(
                "Metadata تشير إلى برنامج تحرير: "
                + ", ".join(sorted(set(found_editors)))
            )

            # وزن صغير فقط؛ البرنامج وحده لا يثبت التزوير
            result["score"] += 5

        # ----------------------------------------------------
        # CREATION / MODIFICATION DATE
        # ----------------------------------------------------

        creation = str(
            metadata.get("creationDate") or ""
        )

        modified = str(
            metadata.get("modDate") or ""
        )

        if creation and modified and creation != modified:

            result["warnings"].append(
                "تاريخ إنشاء الملف وتاريخ التعديل مختلفان."
            )

            result["score"] += 5

        # ----------------------------------------------------
        # DOCUMENT JAVASCRIPT
        # ----------------------------------------------------

        try:
            js = doc.get_xml_metadata()

            if js and "javascript" in js.lower():
                result["javascript"] = True

        except Exception:
            pass

        if result["javascript"]:
            result["suspicious"].append(
                "وجود JavaScript داخل PDF."
            )
            result["score"] += 15

        # ----------------------------------------------------
        # EMBEDDED FILES
        # ----------------------------------------------------

        try:
            embedded = doc.embfile_names()

            result["embedded_files"] = len(
                embedded
            )

        except Exception:
            result["embedded_files"] = 0

        if result["embedded_files"] > 0:

            result["warnings"].append(
                f"الملف يحتوي على "
                f"{result['embedded_files']} ملف/ملفات مضمّنة."
            )

            result["score"] += 8

        # ----------------------------------------------------
        # FONTS / IMAGES / ANNOTATIONS
        # ----------------------------------------------------

        fonts = set()

        page_text_stats = []

        for page_number in range(len(doc)):

            page = doc[page_number]

            # ----------------------------------------------
            # TEXT
            # ----------------------------------------------

            text = page.get_text("text") or ""

            words = page.get_text("words") or []

            page_text_stats.append({
                "page": page_number + 1,
                "chars": len(text),
                "words": len(words),
            })

            # ----------------------------------------------
            # FONTS
            # ----------------------------------------------

            try:

                page_fonts = page.get_fonts(
                    full=True
                )

                for font in page_fonts:

                    if len(font) > 3:
                        font_name = str(
                            font[3] or ""
                        ).strip()

                        if font_name:
                            fonts.add(font_name)

            except Exception:
                pass

            # ----------------------------------------------
            # IMAGES
            # ----------------------------------------------

            try:

                images = page.get_images(
                    full=True
                )

                result["images"] += len(images)

            except Exception:
                pass

            # ----------------------------------------------
            # ANNOTATIONS
            # ----------------------------------------------

            try:

                annots = page.annots()

                if annots:

                    for _ in annots:
                        result["annotations"] += 1

            except Exception:
                pass

        result["fonts"] = sorted(fonts)

        # ----------------------------------------------------
        # FONT ANALYSIS
        # ----------------------------------------------------

        if len(result["fonts"]) >= 6:

            result["warnings"].append(
                f"عدد الخطوط مختلف نسبيًا: "
                f"{len(result['fonts'])}"
            )

            result["score"] += 5

        # ----------------------------------------------------
        # ANNOTATIONS
        # ----------------------------------------------------

        if result["annotations"] > 0:

            result["warnings"].append(
                f"وجود {result['annotations']} annotation/"
                "تعليق أو عنصر تفاعلي."
            )

            result["score"] += min(
                10,
                result["annotations"]
            )

        # ----------------------------------------------------
        # INCREMENTAL / EOF MARKERS
        # ----------------------------------------------------

        try:

            raw = path.read_bytes()

            eof_count = len(
                re.findall(
                    rb"%%EOF",
                    raw,
                )
            )

            startxref_count = len(
                re.findall(
                    rb"startxref",
                    raw,
                )
            )

            if eof_count > 1:

                result["incremental"] = True

                result["warnings"].append(
                    f"وجدنا {eof_count} علامات %%EOF؛ "
                    "قد يدل ذلك على تحديثات incremental."
                )

                result["score"] += 8

            if startxref_count > 1:

                result["warnings"].append(
                    f"وجدنا {startxref_count} startxref."
                )

        except Exception:
            pass

        # ----------------------------------------------------
        # FORM FIELDS
        # ----------------------------------------------------

        try:

            widgets_found = 0

            for page_number in range(len(doc)):

                page = doc[page_number]

                widgets = page.widgets()

                if widgets:

                    for _ in widgets:
                        widgets_found += 1

            if widgets_found > 0:

                result["forms"] = True

                result["warnings"].append(
                    f"PDF يحتوي على {widgets_found} "
                    "form field."
                )

                result["score"] += 3

        except Exception:
            pass

        # ----------------------------------------------------
        # DIGITAL SIGNATURE DETECTION
        # ----------------------------------------------------

        try:

            for page_number in range(len(doc)):

                page = doc[page_number]

                widgets = page.widgets()

                if not widgets:
                    continue

                for widget in widgets:

                    field_type = str(
                        getattr(
                            widget,
                            "field_type",
                            "",
                        )
                    ).lower()

                    field_name = str(
                        getattr(
                            widget,
                            "field_name",
                            "",
                        )
                    ).lower()

                    if (
                        "signature" in field_type
                        or "signature" in field_name
                    ):

                        result["signed"] = True

        except Exception:
            pass

        # ----------------------------------------------------
        # SCORE LIMIT
        # ----------------------------------------------------

        result["score"] = max(
            0,
            min(
                100,
                int(result["score"])
            )
        )

        # ----------------------------------------------------
        # CLASSIFICATION
        # ----------------------------------------------------

        if result["score"] >= 50:

            result["status"] = (
                "🔴 HIGH SUSPICION"
            )

        elif result["score"] >= 25:

            result["status"] = (
                "🟠 SUSPICIOUS"
            )

        else:

            result["status"] = (
                "🟢 NO STRONG TAMPERING INDICATORS"
            )

        return result

    finally:

        if doc is not None:

            try:
                doc.close()
            except Exception:
                pass


# ============================================================
# REPORT
# ============================================================

def make_report(result):

    size_mb = result["size"] / (
        1024 * 1024
    )

    metadata = result["metadata"]

    report = []

    report.append(
        "🔎 LEX PDF FORENSIC"
    )

    report.append("")

    report.append(
        f"📄 File: {result['filename']}"
    )

    report.append(
        f"📦 Size: {size_mb:.2f} MB"
    )

    report.append(
        f"📑 Pages: {result['pages']}"
    )

    report.append("")

    report.append(
        f"🚦 Status: {result['status']}"
    )

    report.append(
        f"📊 Risk score: {result['score']}/100"
    )

    report.append("")

    report.append(
        "🔐 FILE STRUCTURE"
    )

    report.append(
        f"• Encrypted: "
        f"{'YES' if result['encrypted'] else 'NO'}"
    )

    report.append(
        f"• Digital signature: "
        f"{'FOUND' if result['signed'] else 'NOT DETECTED'}"
    )

    report.append(
        f"• Embedded files: "
        f"{result['embedded_files']}"
    )

    report.append(
        f"• Images: "
        f"{result['images']}"
    )

    report.append(
        f"• Annotations: "
        f"{result['annotations']}"
    )

    report.append(
        f"• Forms: "
        f"{'YES' if result['forms'] else 'NO'}"
    )

    report.append("")

    report.append(
        "📝 METADATA"
    )

    creator = metadata.get("creator") or "N/A"
    producer = metadata.get("producer") or "N/A"
    creation = metadata.get("creationDate") or "N/A"
    modified = metadata.get("modDate") or "N/A"

    report.append(
        f"• Creator: {truncate(creator)}"
    )

    report.append(
        f"• Producer: {truncate(producer)}"
    )

    report.append(
        f"• Created: {truncate(creation)}"
    )

    report.append(
        f"• Modified: {truncate(modified)}"
    )

    if result["warnings"]:

        report.append("")

        report.append(
            "⚠️ INDICATORS"
        )

        for warning in result["warnings"][:8]:

            report.append(
                "• " + truncate(warning, 250)
            )

    if result["suspicious"]:

        report.append("")

        report.append(
            "🚨 SUSPICIOUS"
        )

        for item in result["suspicious"][:8]:

            report.append(
                "• " + truncate(item, 250)
            )

    report.append("")

    report.append(
        "🔑 SHA-256"
    )

    report.append(
        result["sha256"]
    )

    report.append("")

    report.append(
        "⚠️ هذه نتيجة تحليل تقني."
    )

    report.append(
        "لا تعتبر إثباتًا قانونيًا بأن الوثيقة مزورة."
    )

    report.append("")

    report.append(
        "By LEX"
    )

    return "\n".join(report)


# ============================================================
# /START
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    await update.message.reply_text(
        "🤖 LEX PDF Forensic Bot\n\n"
        "📄 ابعثلي PDF وأنا نفحصه.\n\n"
        "🔎 نفحص:\n"
        "• Metadata\n"
        "• Fonts\n"
        "• Images\n"
        "• Annotations\n"
        "• JavaScript\n"
        "• Embedded files\n"
        "• PDF structure\n"
        "• Incremental updates\n"
        "• Digital signature indicators\n\n"
        "⚠️ النتيجة تحليل تقني وليست حكمًا قانونيًا.\n\n"
        "By LEX"
    )


# ============================================================
# PDF HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    if not is_allowed_user(update):

        await update.message.reply_text(
            "⛔ غير مسموح لك باستعمال هذا البوت."
        )

        return

    document = update.message.document

    if not document:

        return

    filename = document.file_name or "document.pdf"

    if not filename.lower().endswith(".pdf"):

        await update.message.reply_text(
            "❌ ابعث ملف PDF فقط."
        )

        return

    file_size = document.file_size or 0

    if file_size > MAX_FILE_SIZE:

        await update.message.reply_text(
            f"❌ الملف كبير بزاف.\n"
            f"الحد الأقصى: {MAX_FILE_MB} MB."
        )

        return

    work_dir = Path(
        tempfile.mkdtemp(
            prefix="lex_pdf_"
        )
    )

    pdf_path = (
        work_dir / "document.pdf"
    )

    try:

        await update.message.chat.send_action(
            action=ChatAction.TYPING
        )

        await update.message.reply_text(
            "🔍 استلمت الملف.\n"
            "جاري الفحص..."
        )

        telegram_file = await document.get_file()

        await telegram_file.download_to_drive(
            custom_path=str(pdf_path)
        )

        logger.info(
            "PDF downloaded: %s",
            filename,
        )

        # ----------------------------------------------------
        # ANALYZE
        # ----------------------------------------------------

        try:

            result = await asyncio.to_thread(
                analyze_pdf,
                pdf_path,
            )

        except Exception as e:

            logger.exception(
                "PDF analysis failed: %s",
                e,
            )

            await update.message.reply_text(
                "❌ ماقدرتش نحلل الملف.\n"
                "ممكن يكون PDF تالف أو محمي."
            )

            return

        report = make_report(
            result
        )

        await update.message.reply_text(
            report
        )

        logger.info(
            "Analysis completed | score=%s | file=%s",
            result["score"],
            filename,
        )

    except Exception as e:

        logger.exception(
            "PDF handler error: %s",
            e,
        )

        try:

            await update.message.reply_text(
                "❌ حدث خطأ أثناء معالجة PDF."
            )

        except Exception:
            pass

    finally:

        try:
            shutil.rmtree(
                work_dir,
                ignore_errors=True,
            )
        except Exception:
            pass


# ============================================================
# ERROR HANDLER
# ============================================================

async def error_handler(
    update,
    context: ContextTypes.DEFAULT_TYPE,
):

    error = context.error

    if isinstance(error, Conflict):

        logger.critical(
            "🚨 TELEGRAM 409 CONFLICT"
        )

        logger.critical(
            "Another process is using BOT_TOKEN."
        )

        return

    logger.exception(
        "Telegram error: %s",
        error,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not BOT_TOKEN:

        raise RuntimeError(
            "BOT_TOKEN missing"
        )

    logger.info(
        "======================================"
    )

    logger.info(
        "🚀 LEX PDF FORENSIC BOT"
    )

    logger.info(
        "📄 Max PDF size: %s MB",
        MAX_FILE_MB,
    )

    logger.info(
        "======================================"
    )

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connect_timeout(10)
        .read_timeout(60)
        .write_timeout(60)
        .pool_timeout(20)
        .build()
    )

    # Commands
    app.add_handler(
        CommandHandler(
            "start",
            start,
        )
    )

    # PDF
    app.add_handler(
        MessageHandler(
            filters.Document.PDF,
            handle_pdf,
        )
    )

    # Errors
    app.add_error_handler(
        error_handler
    )

    logger.info(
        "✅ Bot initialized"
    )

    logger.info(
        "▶️ Telegram polling started"
    )

    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main()
