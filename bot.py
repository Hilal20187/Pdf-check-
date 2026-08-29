import os
import re
import hashlib
import logging
import tempfile
import shutil
import asyncio
from pathlib import Path

import fitz
from pypdf import PdfReader

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

MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "25"))
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024

MAX_PAGES = 40

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | LEX | %(message)s",
)

logger = logging.getLogger("LEX")


# ============================================================
# HASH
# ============================================================

def sha256(path: Path):

    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


# ============================================================
# PDF BASIC CHECK
# ============================================================

def check_pdf(path: Path):

    result = {
        "valid": False,
        "pages": 0,
        "metadata": {},
        "fonts": set(),
        "images": 0,
        "annotations": 0,
        "forms": 0,
        "javascript": False,
        "embedded": False,
        "incremental": False,
        "signature": False,
        "text_pages": 0,
        "scan_pages": 0,
        "warnings": [],
        "score": 0,
    }

    doc = None

    # --------------------------------------------------------
    # PyMuPDF
    # --------------------------------------------------------

    try:

        doc = fitz.open(str(path))

        result["valid"] = True
        result["pages"] = doc.page_count

        try:
            result["metadata"] = doc.metadata or {}
        except Exception:
            pass

        pages = min(
            doc.page_count,
            MAX_PAGES,
        )

        for i in range(pages):

            try:

                page = doc[i]

                text = (
                    page.get_text("text")
                    or ""
                ).strip()

                if len(text) >= 10:
                    result["text_pages"] += 1

                images = []

                try:
                    images = page.get_images(
                        full=True
                    )

                    result["images"] += len(
                        images
                    )

                except Exception:
                    pass

                if len(text) < 10 and images:
                    result["scan_pages"] += 1

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

                try:

                    annots = page.annots()

                    if annots:
                        for _ in annots:
                            result[
                                "annotations"
                            ] += 1

                except Exception:
                    pass

            except Exception as e:

                logger.warning(
                    "Page %s failed: %s",
                    i + 1,
                    e,
                )

        try:
            if doc.embfile_names():
                result["embedded"] = True
        except Exception:
            pass

        try:
            xml = doc.get_xml_metadata()

            if xml and (
                "javascript" in xml.lower()
                or "/js" in xml.lower()
            ):
                result["javascript"] = True

        except Exception:
            pass

        doc.close()

    except Exception as e:

        logger.warning(
            "PyMuPDF failed: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    # --------------------------------------------------------
    # pypdf secondary parser
    # --------------------------------------------------------

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        if not result["valid"]:
            result["valid"] = True

        if result["pages"] == 0:
            result["pages"] = len(
                reader.pages
            )

        try:

            if reader.is_encrypted:
                result["warnings"].append(
                    "الملف مشفّر."
                )

        except Exception:
            pass

        try:

            if reader.metadata:

                for key, value in (
                    reader.metadata.items()
                ):

                    if key not in result[
                        "metadata"
                    ]:

                        result["metadata"][
                            key
                        ] = str(value)

        except Exception:
            pass

    except Exception as e:

        logger.warning(
            "pypdf failed: %s",
            e,
        )

    # --------------------------------------------------------
    # RAW PDF FORENSICS
    # --------------------------------------------------------

    try:

        raw = path.read_bytes()

        eof_count = len(
            re.findall(
                rb"%%EOF",
                raw,
            )
        )

        xref_count = len(
            re.findall(
                rb"startxref",
                raw,
            )
        )

        # Multiple EOF / xref can indicate
        # incremental saves, but NOT necessarily fraud.
        if eof_count > 1:

            result["incremental"] = True

            result["warnings"].append(
                f"عدة %%EOF موجودة ({eof_count})."
            )

            result["score"] += min(
                15,
                eof_count * 3,
            )

        if xref_count > 1:

            result["incremental"] = True

            result["warnings"].append(
                f"عدة startxref موجودة ({xref_count})."
            )

            result["score"] += 5

        # JavaScript
        if (
            b"/JavaScript" in raw
            or b"/JS " in raw
            or b"/JS/" in raw
        ):

            result["javascript"] = True

            result["warnings"].append(
                "JavaScript موجود داخل PDF."
            )

            result["score"] += 15

        # Forms
        if b"/AcroForm" in raw:

            result["forms"] = 1

            result["warnings"].append(
                "AcroForm موجود."
            )

            result["score"] += 3

        # Signature
        if (
            b"/Sig" in raw
            or b"/adbe.pkcs7" in raw
            or b"/Adobe.PPKLite" in raw
        ):

            result["signature"] = True

        # Embedded objects
        if (
            b"/EmbeddedFile" in raw
            or b"/Filespec" in raw
        ):

            result["embedded"] = True

            result["score"] += 3

    except Exception as e:

        logger.warning(
            "Raw forensic analysis failed: %s",
            e,
        )

    # --------------------------------------------------------
    # METADATA
    # --------------------------------------------------------

    metadata = " ".join(
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

    found = []

    for editor in suspicious_editors:

        if editor in metadata:
            found.append(editor)

    if found:

        result["warnings"].append(
            "برنامج تحرير ظاهر في metadata: "
            + ", ".join(
                sorted(set(found))
            )
        )

        result["score"] += 8

    # --------------------------------------------------------
    # CREATION / MODIFICATION
    # --------------------------------------------------------

    creation = (
        result["metadata"].get(
            "creationDate"
        )
        or result["metadata"].get(
            "CreationDate"
        )
        or result["metadata"].get(
            "/CreationDate"
        )
    )

    modified = (
        result["metadata"].get(
            "modDate"
        )
        or result["metadata"].get(
            "ModDate"
        )
        or result["metadata"].get(
            "/ModDate"
        )
    )

    if creation and modified:

        if str(creation) != str(modified):

            result["warnings"].append(
                "تاريخ الإنشاء والتعديل مختلف."
            )

            result["score"] += 5

    # --------------------------------------------------------
    # FONT ANALYSIS
    # --------------------------------------------------------

    font_count = len(
        result["fonts"]
    )

    if font_count >= 10:

        result["warnings"].append(
            f"عدد الخطوط مرتفع: {font_count}"
        )

        result["score"] += 5

    # --------------------------------------------------------
    # SCANNED DOCUMENT
    # --------------------------------------------------------

    if (
        result["pages"] > 0
        and result["scan_pages"] > 0
        and result["text_pages"] == 0
    ):

        result["warnings"].append(
            "الوثيقة تبدو Scan/صور."
        )

    # --------------------------------------------------------
    # SCORE
    # --------------------------------------------------------

    result["score"] = max(
        0,
        min(
            100,
            result["score"],
        ),
    )

    if result["score"] >= 50:

        result["status"] = (
            "🔴 اشتباه قوي"
        )

    elif result["score"] >= 25:

        result["status"] = (
            "🟠 مؤشرات تحتاج فحص"
        )

    else:

        result["status"] = (
            "🟢 لا توجد مؤشرات قوية"
        )

    result["fonts"] = sorted(
        result["fonts"]
    )

    return result


# ============================================================
# VISUAL ANALYSIS
# ============================================================

def visual_analysis(path: Path):

    result = {
        "pages": 0,
        "rendered": 0,
        "page_hashes": [],
        "error": None,
    }

    doc = None

    try:

        doc = fitz.open(str(path))

        pages = min(
            doc.page_count,
            MAX_PAGES,
        )

        result["pages"] = pages

        for i in range(pages):

            try:

                page = doc[i]

                pix = page.get_pixmap(
                    matrix=fitz.Matrix(
                        1.5,
                        1.5,
                    ),
                    alpha=False,
                )

                digest = hashlib.sha256(
                    pix.samples
                ).hexdigest()

                result[
                    "page_hashes"
                ].append(
                    digest
                )

                result["rendered"] += 1

            except Exception as e:

                logger.warning(
                    "Visual page %s failed: %s",
                    i + 1,
                    e,
                )

        doc.close()

    except Exception as e:

        result["error"] = str(e)

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    return result


# ============================================================
# FULL FORENSIC ANALYSIS
# ============================================================

def analyze(path):

    logger.info(
        "🔬 Starting forensic analysis"
    )

    structure = check_pdf(
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

def make_report(
    filename,
    path,
    analysis,
):

    s = analysis["structure"]
    v = analysis["visual"]

    meta = s["metadata"]

    creator = (
        meta.get("creator")
        or meta.get("Creator")
        or "N/A"
    )

    producer = (
        meta.get("producer")
        or meta.get("Producer")
        or "N/A"
    )

    created = (
        meta.get("creationDate")
        or meta.get("CreationDate")
        or meta.get("/CreationDate")
        or "N/A"
    )

    modified = (
        meta.get("modDate")
        or meta.get("ModDate")
        or meta.get("/ModDate")
        or "N/A"
    )

    size_mb = (
        path.stat().st_size
        / 1024
        / 1024
    )

    lines = [

        "🔎 LEX PDF FORENSIC PRO",

        "",

        f"📄 {filename}",
        f"📦 الحجم: {size_mb:.2f} MB",
        f"📑 الصفحات: {s['pages']}",

        "",

        f"{s['status']}",
        f"📊 Risk Score: {s['score']}/100",

        "",

        "🔐 تحليل البنية",

        f"• Text pages: {s['text_pages']}",
        f"• Scan pages: {s['scan_pages']}",
        f"• Images: {s['images']}",
        f"• Fonts: {len(s['fonts'])}",
        f"• Annotations: {s['annotations']}",
        f"• Forms: {s['forms']}",
        f"• Embedded files: "
        f"{'YES' if s['embedded'] else 'NO'}",
        f"• JavaScript: "
        f"{'YES' if s['javascript'] else 'NO'}",
        f"• Incremental updates: "
        f"{'YES' if s['incremental'] else 'NO'}",
        f"• Signature indicator: "
        f"{'YES' if s['signature'] else 'NO'}",

        "",

        "📝 Metadata",

        f"• Creator: {str(creator)[:150]}",
        f"• Producer: {str(producer)[:150]}",
        f"• Created: {str(created)[:150]}",
        f"• Modified: {str(modified)[:150]}",
    ]

    if s["warnings"]:

        lines += [
            "",
            "⚠️ مؤشرات:",
        ]

        for warning in s[
            "warnings"
        ][:12]:

            lines.append(
                "• " + warning[:220]
            )

    lines += [
        "",
        "🖼️ Visual rendering",
        f"• Rendered pages: "
        f"{v['rendered']}/{v['pages']}",
    ]

    if v["error"]:

        lines.append(
            "• Visual error: "
            + str(v["error"])[:150]
        )

    lines += [
        "",
        "🔑 SHA-256",
        sha256(path),

        "",
        "⚠️ مهم:",
        "هذا التحليل يكشف مؤشرات تقنية فقط.",
        "لا يمكن إثبات التزوير 100% من ملف واحد بدون الأصل.",
        "",
        "By LEX",
    ]

    return "\n".join(lines)


# ============================================================
# START
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    await update.message.reply_text(
        "🤖 LEX PDF FORENSIC PRO\n\n"
        "📄 ابعث PDF للتحليل.\n\n"
        "أفحص البنية، metadata، الخطوط، "
        "الصور، annotations، JavaScript، "
        "incremental updates، وrendering.\n\n"
        "⚠️ النتيجة مؤشر تقني وليست إثباتًا "
        "قانونيًا للتزوير."
    )


# ============================================================
# PDF HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

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

    file_size = document.file_size or 0

    if file_size > MAX_FILE_SIZE:

        await update.message.reply_text(
            f"❌ الملف كبير.\n"
            f"الحد الأقصى: {MAX_FILE_MB} MB."
        )

        return

    workdir = Path(
        tempfile.mkdtemp(
            prefix="lex_"
        )
    )

    path = (
        workdir
        / "document.pdf"
    )

    try:

        await update.message.chat.send_action(
            ChatAction.TYPING
        )

        await update.message.reply_text(
            "🔍 استلمت الملف.\n"
            "جاري الفحص الجنائي للـPDF..."
        )

        tg_file = await document.get_file()

        await tg_file.download_to_drive(
            custom_path=str(path)
        )

        if not path.exists():
            raise RuntimeError(
                "Download failed"
            )

        if path.stat().st_size == 0:
            raise RuntimeError(
                "Empty file"
            )

        # PDF signature
        with open(
            path,
            "rb",
        ) as f:

            header = f.read(8)

        if not header.startswith(
            b"%PDF"
        ):

            await update.message.reply_text(
                "❌ الملف لا يبدو PDF صالحًا."
            )

            return

        # CPU-heavy work خارج event loop
        analysis = await asyncio.to_thread(
            analyze,
            path,
        )

        report = make_report(
            filename,
            path,
            analysis,
        )

        await update.message.reply_text(
            report
        )

        logger.info(
            "✅ Analysis completed | %s | score=%s",
            filename,
            analysis[
                "structure"
            ]["score"],
        )

    except Exception as e:

        logger.exception(
            "PDF handler failed: %s",
            e,
        )

        try:

            await update.message.reply_text(
                "❌ ماقدرتش نكمل التحليل.\n\n"
                "الملف ما طيّحش البوت، "
                "جرب PDF آخر."
            )

        except Exception:
            pass

    finally:

        shutil.rmtree(
            workdir,
            ignore_errors=True,
        )


# ============================================================
# ERROR HANDLER
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
            "🚨 409 CONFLICT - "
            "another instance is using BOT_TOKEN"
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

    if isinstance(
        error,
        (
            TimedOut,
            NetworkError,
        ),
    ):

        logger.warning(
            "Telegram network error: %s",
            error,
        )

        return

    logger.exception(
        "Unhandled Telegram error: %s",
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
        "🚀 LEX PDF FORENSIC PRO starting..."
    )

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connect_timeout(15)
        .read_timeout(90)
        .write_timeout(90)
        .pool_timeout(30)
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
        "✅ Bot ready"
    )

    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main()
