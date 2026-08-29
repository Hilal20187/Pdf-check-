import os
import re
import json
import shutil
import hashlib
import logging
import tempfile
import asyncio
from pathlib import Path

import fitz  # PyMuPDF
from pypdf import PdfReader

from telegram import Update
from telegram.constants import ChatAction
from telegram.error import (
    Conflict,
    NetworkError,
    TimedOut,
    RetryAfter,
)
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
ADMIN_ID = os.getenv("ADMIN_ID", "").strip()

MAX_FILE_MB = 25
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

# أقصى عدد صفحات للتحليل البصري
MAX_VISUAL_PAGES = 30


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("LEX-PDF")


# ============================================================
# BASIC HELPERS
# ============================================================

def sha256_file(path: Path):

    h = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def truncate(value, maximum=180):

    value = str(value or "").strip()

    if len(value) <= maximum:
        return value

    return value[:maximum - 3] + "..."


def allowed_user(update: Update):

    if not ADMIN_ID:
        return True

    user = update.effective_user

    if not user:
        return False

    return str(user.id) == ADMIN_ID


# ============================================================
# PDF OPEN - METHOD 1
# ============================================================

def open_with_pymupdf(path):

    try:

        doc = fitz.open(str(path))

        # بعض الملفات تحتاج repair/reload
        if doc.page_count > 0:
            return doc

        doc.close()

    except Exception as e:

        logger.warning(
            "PyMuPDF failed: %s",
            e,
        )

    return None


# ============================================================
# PDF OPEN - METHOD 2
# ============================================================

def open_with_pypdf(path):

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        # محاولة التعامل مع encrypted PDF
        if reader.is_encrypted:

            try:
                reader.decrypt("")
            except Exception:
                pass

        return reader

    except Exception as e:

        logger.warning(
            "pypdf failed: %s",
            e,
        )

    return None


# ============================================================
# METADATA USING PYPDF
# ============================================================

def extract_pypdf_metadata(reader):

    result = {}

    try:

        metadata = reader.metadata

        if metadata:

            for key, value in metadata.items():

                result[str(key)] = truncate(
                    value,
                    300,
                )

    except Exception as e:

        logger.warning(
            "Metadata error: %s",
            e,
        )

    return result


# ============================================================
# PDF STRUCTURE ANALYSIS
# ============================================================

def analyze_structure(path):

    result = {
        "pages": 0,
        "metadata": {},
        "fonts": set(),
        "images": 0,
        "annotations": 0,
        "forms": 0,
        "javascript": False,
        "embedded_files": 0,
        "encrypted": False,
        "signature": False,
        "text_pages": 0,
        "image_only_pages": 0,
        "warnings": [],
        "score": 0,
    }

    doc = None
    reader = None

    # ========================================================
    # PyMuPDF
    # ========================================================

    try:

        doc = open_with_pymupdf(path)

        if doc:

            result["pages"] = doc.page_count

            try:
                result["encrypted"] = bool(
                    doc.is_encrypted
                )
            except Exception:
                pass

            # ------------------------------
            # Metadata
            # ------------------------------

            try:

                metadata = doc.metadata or {}

                for key, value in metadata.items():

                    if value:
                        result["metadata"][key] = (
                            str(value)
                        )

            except Exception:
                pass

            # ------------------------------
            # Pages
            # ------------------------------

            for page_index in range(
                min(doc.page_count, MAX_VISUAL_PAGES)
            ):

                try:

                    page = doc[page_index]

                    # Text
                    text = (
                        page.get_text("text")
                        or ""
                    ).strip()

                    # Images
                    try:

                        images = page.get_images(
                            full=True
                        )

                        result["images"] += len(
                            images
                        )

                    except Exception:
                        pass

                    # Fonts
                    try:

                        fonts = page.get_fonts(
                            full=True
                        )

                        for font in fonts:

                            if len(font) > 3:

                                name = str(
                                    font[3] or ""
                                ).strip()

                                if name:
                                    result[
                                        "fonts"
                                    ].add(name)

                    except Exception:
                        pass

                    # Annotations
                    try:

                        annots = page.annots()

                        if annots:

                            for _ in annots:
                                result[
                                    "annotations"
                                ] += 1

                    except Exception:
                        pass

                    # Text / scanned page
                    if len(text) >= 10:

                        result[
                            "text_pages"
                        ] += 1

                    else:

                        # الصفحة ممكن تكون scan
                        if images:

                            result[
                                "image_only_pages"
                            ] += 1

                except Exception as e:

                    logger.warning(
                        "Page %s analysis failed: %s",
                        page_index + 1,
                        e,
                    )

            # ------------------------------
            # Embedded files
            # ------------------------------

            try:

                names = doc.embfile_names()

                result[
                    "embedded_files"
                ] = len(names)

            except Exception:
                pass

            # ------------------------------
            # XML metadata / JS
            # ------------------------------

            try:

                xml = doc.get_xml_metadata()

                if xml and (
                    "javascript" in xml.lower()
                    or "/js" in xml.lower()
                ):

                    result["javascript"] = True

            except Exception:
                pass

            try:
                doc.close()
            except Exception:
                pass

    except Exception as e:

        logger.warning(
            "Complete PyMuPDF analysis failed: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    # ========================================================
    # pypdf fallback / second analysis
    # ========================================================

    try:

        reader = open_with_pypdf(path)

        if reader:

            if result["pages"] == 0:

                try:
                    result["pages"] = len(
                        reader.pages
                    )
                except Exception:
                    pass

            # Metadata
            pypdf_meta = (
                extract_pypdf_metadata(
                    reader
                )
            )

            for key, value in pypdf_meta.items():

                if key not in result[
                    "metadata"
                ]:

                    result["metadata"][key] = value

            # Encryption
            try:

                if reader.is_encrypted:
                    result["encrypted"] = True

            except Exception:
                pass

    except Exception as e:

        logger.warning(
            "pypdf fallback failed: %s",
            e,
        )

    # ========================================================
    # RAW PDF ANALYSIS
    # ========================================================

    try:

        raw = path.read_bytes()

        # ----------------------------------------------------
        # Multiple EOF markers
        # ----------------------------------------------------

        eof_count = len(
            re.findall(
                rb"%%EOF",
                raw,
            )
        )

        if eof_count > 1:

            result["warnings"].append(
                f"الملف يحتوي على {eof_count} "
                "علامات %%EOF."
            )

            result["score"] += min(
                10,
                eof_count * 2,
            )

        # ----------------------------------------------------
        # startxref
        # ----------------------------------------------------

        startxref_count = len(
            re.findall(
                rb"startxref",
                raw,
            )
        )

        if startxref_count > 1:

            result["warnings"].append(
                "وجود عدة بنى xref قد يشير "
                "إلى incremental updates."
            )

            result["score"] += 5

        # ----------------------------------------------------
        # JavaScript
        # ----------------------------------------------------

        js_patterns = [
            rb"/JavaScript",
            rb"/JS ",
            rb"/JS/",
        ]

        js_found = any(
            pattern in raw
            for pattern in js_patterns
        )

        if js_found:

            result["javascript"] = True

            result["warnings"].append(
                "وجود JavaScript داخل PDF."
            )

            result["score"] += 15

        # ----------------------------------------------------
        # AcroForm
        # ----------------------------------------------------

        if b"/AcroForm" in raw:

            result["forms"] += 1

            result["warnings"].append(
                "وجود نموذج تفاعلي AcroForm."
            )

            result["score"] += 3

        # ----------------------------------------------------
        # Signature
        # ----------------------------------------------------

        if (
            b"/Sig" in raw
            or b"/Adobe.PPKLite" in raw
            or b"/adbe.pkcs7" in raw
        ):

            result["signature"] = True

        # ----------------------------------------------------
        # Embedded files
        # ----------------------------------------------------

        if (
            b"/EmbeddedFile" in raw
            or b"/Filespec" in raw
        ):

            if result["embedded_files"] == 0:

                result["embedded_files"] = 1

    except Exception as e:

        logger.warning(
            "Raw analysis failed: %s",
            e,
        )

    # ========================================================
    # METADATA ANALYSIS
    # ========================================================

    metadata_text = " ".join(
        str(v).lower()
        for v in result["metadata"].values()
    )

    suspicious_editors = [
        "photoshop",
        "gimp",
        "illustrator",
        "indesign",
        "canva",
        "nitro",
        "foxit",
    ]

    found_editors = []

    for editor in suspicious_editors:

        if editor in metadata_text:

            found_editors.append(
                editor
            )

    if found_editors:

        result["warnings"].append(
            "Metadata تشير إلى برنامج تحرير: "
            + ", ".join(
                sorted(
                    set(found_editors)
                )
            )
        )

        # لا نعطي وزن كبير
        result["score"] += 5

    # --------------------------------------------------------
    # Created / Modified
    # --------------------------------------------------------

    creation = (
        result["metadata"].get(
            "creationDate"
        )
        or result["metadata"].get(
            "CreationDate"
        )
    )

    modified = (
        result["metadata"].get(
            "modDate"
        )
        or result["metadata"].get(
            "ModDate"
        )
    )

    if creation and modified:

        if str(creation) != str(modified):

            result["warnings"].append(
                "تاريخ الإنشاء والتعديل مختلفان."
            )

            result["score"] += 5

    # ========================================================
    # SCANNED DOCUMENT
    # ========================================================

    if (
        result["pages"] > 0
        and result["image_only_pages"] > 0
        and result["text_pages"] == 0
    ):

        result["warnings"].append(
            "الوثيقة تبدو Scan/صور بدون نص PDF."
        )

    # ========================================================
    # FONTS
    # ========================================================

    result["fonts"] = sorted(
        result["fonts"]
    )

    if len(result["fonts"]) >= 8:

        result["warnings"].append(
            f"عدد الخطوط داخل الملف: "
            f"{len(result['fonts'])}"
        )

        result["score"] += 5

    # ========================================================
    # LIMIT SCORE
    # ========================================================

    result["score"] = max(
        0,
        min(
            100,
            int(result["score"])
        ),
    )

    # ========================================================
    # STATUS
    # ========================================================

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
            "🟢 NO STRONG INDICATORS"
        )

    return result


# ============================================================
# VISUAL ANALYSIS
# ============================================================

def visual_analysis(path):

    result = {
        "rendered_pages": 0,
        "page_hashes": [],
        "error": None,
    }

    doc = None

    try:

        doc = fitz.open(str(path))

        pages = min(
            doc.page_count,
            MAX_VISUAL_PAGES,
        )

        for i in range(pages):

            try:

                page = doc[i]

                # Render page at moderate resolution
                pix = page.get_pixmap(
                    matrix=fitz.Matrix(
                        1.5,
                        1.5,
                    ),
                    alpha=False,
                )

                # Hash للصورة الناتجة
                image_hash = hashlib.sha256(
                    pix.samples
                ).hexdigest()

                result[
                    "page_hashes"
                ].append(
                    image_hash
                )

                result[
                    "rendered_pages"
                ] += 1

            except Exception as e:

                logger.warning(
                    "Visual page %s failed: %s",
                    i + 1,
                    e,
                )

        doc.close()

    except Exception as e:

        result["error"] = str(e)

        logger.warning(
            "Visual analysis failed: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    return result


# ============================================================
# FULL ANALYSIS
# ============================================================

def full_analysis(path):

    logger.info(
        "🔬 Starting forensic analysis..."
    )

    structure = analyze_structure(
        path
    )

    visual = visual_analysis(
        path
    )

    return {
        "structure": structure,
        "visual": visual,
    }


# ============================================================
# REPORT
# ============================================================

def build_report(
    filename,
    file_size,
    sha256,
    analysis,
):

    data = analysis["structure"]

    size_mb = (
        file_size
        / 1024
        / 1024
    )

    metadata = data["metadata"]

    creator = (
        metadata.get("creator")
        or metadata.get("/Creator")
        or "N/A"
    )

    producer = (
        metadata.get("producer")
        or metadata.get("/Producer")
        or "N/A"
    )

    creation = (
        metadata.get("creationDate")
        or metadata.get("/CreationDate")
        or "N/A"
    )

    modified = (
        metadata.get("modDate")
        or metadata.get("/ModDate")
        or "N/A"
    )

    report = []

    report.append(
        "🔎 LEX PDF FORENSIC PRO"
    )

    report.append("")

    report.append(
        f"📄 {truncate(filename, 100)}"
    )

    report.append(
        f"📦 Size: {size_mb:.2f} MB"
    )

    report.append(
        f"📑 Pages: {data['pages']}"
    )

    report.append("")

    report.append(
        f"🚦 {data['status']}"
    )

    report.append(
        f"📊 Risk Score: {data['score']}/100"
    )

    report.append("")

    report.append(
        "🔐 STRUCTURE"
    )

    report.append(
        f"• Encrypted: "
        f"{'YES' if data['encrypted'] else 'NO'}"
    )

    report.append(
        f"• Digital signature indicator: "
        f"{'FOUND' if data['signature'] else 'NOT DETECTED'}"
    )

    report.append(
        f"• Text pages: {data['text_pages']}"
    )

    report.append(
        f"• Image/scan pages: "
        f"{data['image_only_pages']}"
    )

    report.append(
        f"• Images: {data['images']}"
    )

    report.append(
        f"• Fonts: {len(data['fonts'])}"
    )

    report.append(
        f"• Annotations: {data['annotations']}"
    )

    report.append(
        f"• Embedded files: "
        f"{data['embedded_files']}"
    )

    report.append("")

    report.append(
        "📝 METADATA"
    )

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

    if data["warnings"]:

        report.append("")

        report.append(
            "⚠️ INDICATORS"
        )

        for warning in data[
            "warnings"
        ][:10]:

            report.append(
                "• "
                + truncate(
                    warning,
                    250,
                )
            )

    report.append("")

    report.append(
        "🖼️ VISUAL ANALYSIS"
    )

    report.append(
        f"• Rendered pages: "
        f"{analysis['visual']['rendered_pages']}"
    )

    if analysis[
        "visual"
    ]["error"]:

        report.append(
            "• Visual warning: "
            + truncate(
                analysis["visual"]["error"],
                150,
            )
        )

    report.append("")

    report.append(
        "🔑 SHA-256"
    )

    report.append(
        sha256
    )

    report.append("")

    report.append(
        "⚠️ ملاحظة:"
    )

    report.append(
        "الـRisk Score مؤشر تقني فقط."
    )

    report.append(
        "لا يثبت وحده أن الوثيقة مزورة."
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
        "🤖 LEX PDF FORENSIC PRO\n\n"
        "📄 ابعثلي PDF للتحليل.\n\n"
        "🔎 نفحص:\n"
        "• PDF structure\n"
        "• Metadata\n"
        "• Fonts\n"
        "• Images\n"
        "• Annotations\n"
        "• JavaScript\n"
        "• Embedded files\n"
        "• Digital signature indicators\n"
        "• Scanned pages\n"
        "• Incremental updates\n"
        "• Visual rendering\n\n"
        "⚠️ النتيجة مؤشر تقني وليست حكمًا قانونيًا.\n\n"
        "By LEX"
    )


# ============================================================
# PDF HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    if not allowed_user(update):

        await update.message.reply_text(
            "⛔ غير مسموح لك باستعمال هذا البوت."
        )

        return

    document = update.message.document

    if not document:
        return

    filename = (
        document.file_name
        or "document.pdf"
    )

    if not filename.lower().endswith(
        ".pdf"
    ):

        await update.message.reply_text(
            "❌ ابعث PDF فقط."
        )

        return

    size = document.file_size or 0

    if size > MAX_FILE_SIZE:

        await update.message.reply_text(
            f"❌ الملف كبير.\n"
            f"الحد الأقصى {MAX_FILE_MB} MB."
        )

        return

    work_dir = Path(
        tempfile.mkdtemp(
            prefix="lex_pdf_"
        )
    )

    path = (
        work_dir
        / "document.pdf"
    )

    try:

        await update.message.chat.send_action(
            action=ChatAction.TYPING
        )

        await update.message.reply_text(
            "🔍 استلمت الملف.\n"
            "جاري التحليل المتعدد..."
        )

        # ====================================================
        # DOWNLOAD
        # ====================================================

        tg_file = await document.get_file()

        await tg_file.download_to_drive(
            custom_path=str(path)
        )

        logger.info(
            "📥 PDF downloaded: %s",
            filename,
        )

        # ====================================================
        # BASIC FILE CHECK
        # ====================================================

        if not path.exists():

            raise RuntimeError(
                "Downloaded file missing"
            )

        if path.stat().st_size == 0:

            raise RuntimeError(
                "Downloaded PDF is empty"
            )

        # ====================================================
        # PDF HEADER CHECK
        # ====================================================

        with open(
            path,
            "rb",
        ) as f:

            header = f.read(8)

        if not header.startswith(
            b"%PDF"
        ):

            await update.message.reply_text(
                "❌ الملف المرسل ليس PDF صالحًا."
            )

            return

        # ====================================================
        # ANALYSIS
        # ====================================================

        analysis = await asyncio.to_thread(
            full_analysis,
            path,
        )

        sha256 = sha256_file(
            path
        )

        report = build_report(
            filename,
            path.stat().st_size,
            sha256,
            analysis,
        )

        await update.message.reply_text(
            report
        )

        logger.info(
            "✅ Analysis completed: %s | score=%s",
            filename,
            analysis[
                "structure"
            ]["score"],
        )

    except Exception as e:

        logger.exception(
            "❌ Handler failed: %s",
            e,
        )

        try:

            await update.message.reply_text(
                "❌ صار خطأ غير متوقع أثناء التحليل.\n"
                "الملف ما طيّحش البوت، عاود ابعثه."
            )

        except Exception:
            pass

    finally:

        shutil.rmtree(
            work_dir,
            ignore_errors=True,
        )


# ============================================================
# TELEGRAM ERROR HANDLER
# ============================================================

async def error_handler(
    update,
    context: ContextTypes.DEFAULT_TYPE,
):

    error = context.error

    if isinstance(
        error,
        Conflict,
    ):

        logger.critical(
            "🚨 TELEGRAM 409 CONFLICT"
        )

        logger.critical(
            "Another instance is using BOT_TOKEN."
        )

        return

    if isinstance(
        error,
        RetryAfter,
    ):

        logger.warning(
            "Telegram rate limit: %s",
            error.retry_after,
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
        "🚀 LEX PDF FORENSIC PRO"
    )

    logger.info(
        "📄 Max file: %s MB",
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

    app.add_handler(
        CommandHandler(
            "start",
            start,
        )
    )

    app.add_handler(
        MessageHandler(
            filters.Document.PDF,
            handle_pdf,
        )
    )

    app.add_error_handler(
        error_handler
    )

    logger.info(
        "✅ Bot initialized"
    )

    logger.info(
        "▶️ Polling started"
    )

    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main() 
