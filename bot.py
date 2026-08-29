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

MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "25"))
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024
MAX_PAGES = 50

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | LEX | %(message)s",
)

logger = logging.getLogger("LEX")


# ============================================================
# KNOWN PDF EDITORS / REWRITERS
# ============================================================

EDITORS = {
    "sejda": "Sejda",
    "smallpdf": "Smallpdf",
    "ilovepdf": "iLovePDF",
    "ilovePDF": "iLovePDF",
    "pdfescape": "PDFescape",
    "nitro": "Nitro PDF",
    "foxit": "Foxit PDF",
    "adobe acrobat": "Adobe Acrobat",
    "acrobat": "Adobe Acrobat",
    "photoshop": "Adobe Photoshop",
    "illustrator": "Adobe Illustrator",
    "indesign": "Adobe InDesign",
    "gimp": "GIMP",
    "canva": "Canva",
    "pdfsam": "PDFsam",
    "libreoffice": "LibreOffice",
    "wkhtmltopdf": "wkhtmltopdf",
    "weasyprint": "WeasyPrint",
}


# ============================================================
# HELPERS
# ============================================================

def clean(value):
    if value is None:
        return ""

    return str(value).strip()


def find_editors(text):

    found = []

    lower = text.lower()

    for key, name in EDITORS.items():

        if key.lower() in lower:
            if name not in found:
                found.append(name)

    return found


def sha256(path):

    h = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


# ============================================================
# RAW PDF FORENSICS
# ============================================================

def raw_forensics(path):

    raw = path.read_bytes()

    result = {
        "size": len(raw),
        "eof": 0,
        "xref": 0,
        "startxref": 0,
        "objects": 0,
        "streams": 0,
        "javascript": False,
        "embedded": False,
        "signatures": False,
        "editors": [],
        "warnings": [],
        "score": 0,
    }

    # --------------------------------------------------------
    # EOF / revisions
    # --------------------------------------------------------

    result["eof"] = len(
        re.findall(
            rb"%%EOF",
            raw,
        )
    )

    result["startxref"] = len(
        re.findall(
            rb"startxref",
            raw,
        )
    )

    result["xref"] = len(
        re.findall(
            rb"(?:^|\n)xref(?:\s|\n)",
            raw,
            re.MULTILINE,
        )
    )

    # --------------------------------------------------------
    # Objects
    # --------------------------------------------------------

    result["objects"] = len(
        re.findall(
            rb"\n\d+\s+\d+\s+obj\b",
            raw,
        )
    )

    result["streams"] = len(
        re.findall(
            rb"\bstream\b",
            raw,
        )
    )

    # --------------------------------------------------------
    # Dangerous / special objects
    # --------------------------------------------------------

    if (
        b"/JavaScript" in raw
        or b"/JavaScript " in raw
        or b"/JS " in raw
        or b"/JS/" in raw
    ):

        result["javascript"] = True

        result["warnings"].append(
            "JavaScript موجود داخل الملف."
        )

        result["score"] += 15

    if (
        b"/EmbeddedFile" in raw
        or b"/Filespec" in raw
    ):

        result["embedded"] = True

        result["warnings"].append(
            "ملف يحتوي على embedded objects/files."
        )

        result["score"] += 3

    if (
        b"/ByteRange" in raw
        or b"/adbe.pkcs7" in raw
        or b"/Adobe.PPKLite" in raw
    ):

        result["signatures"] = True

    # --------------------------------------------------------
    # Editor fingerprints
    # --------------------------------------------------------

    try:
        raw_text = raw.decode(
            "latin-1",
            errors="ignore",
        )
    except Exception:
        raw_text = ""

    result["editors"] = find_editors(
        raw_text
    )

    if result["editors"]:

        for editor in result["editors"]:

            result["warnings"].append(
                f"أثر برنامج PDF: {editor}"
            )

        # Strong indicator of processing,
        # NOT automatic proof of fraud.
        result["score"] += 35

    # --------------------------------------------------------
    # Incremental updates
    # --------------------------------------------------------

    if result["eof"] > 1:

        result["warnings"].append(
            f"عدة PDF revisions محتملة: "
            f"{result['eof']} %%EOF"
        )

        result["score"] += min(
            20,
            (result["eof"] - 1) * 5,
        )

    if result["startxref"] > 1:

        result["warnings"].append(
            f"عدة startxref: "
            f"{result['startxref']}"
        )

        result["score"] += 5

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# PDF INFO + XMP
# ============================================================

def metadata_forensics(path):

    result = {
        "info": {},
        "xmp": "",
        "editors": [],
        "warnings": [],
        "score": 0,
    }

    # --------------------------------------------------------
    # pypdf Info
    # --------------------------------------------------------

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        metadata = reader.metadata

        if metadata:

            for key, value in metadata.items():

                key = clean(key)
                value = clean(value)

                if key and value:

                    result["info"][key] = value

    except Exception as e:

        logger.warning(
            "Metadata reader failed: %s",
            e,
        )

    # --------------------------------------------------------
    # PyMuPDF XMP
    # --------------------------------------------------------

    try:

        doc = fitz.open(str(path))

        try:

            xmp = doc.get_xml_metadata()

            if xmp:

                result["xmp"] = xmp

        except Exception:
            pass

        doc.close()

    except Exception as e:

        logger.warning(
            "XMP extraction failed: %s",
            e,
        )

    # --------------------------------------------------------
    # Combined metadata
    # --------------------------------------------------------

    info_text = "\n".join(
        f"{k}: {v}"
        for k, v in result["info"].items()
    )

    combined = (
        info_text
        + "\n"
        + result["xmp"]
    )

    result["editors"] = find_editors(
        combined
    )

    if result["editors"]:

        for editor in result["editors"]:

            result["warnings"].append(
                f"Metadata/XMP يشير إلى: {editor}"
            )

        result["score"] += 40

    # --------------------------------------------------------
    # Creation / Modification
    # --------------------------------------------------------

    creation_keys = [
        "/CreationDate",
        "CreationDate",
        "creationDate",
    ]

    modification_keys = [
        "/ModDate",
        "ModDate",
        "modDate",
    ]

    creation = ""

    modified = ""

    for key in creation_keys:

        if key in result["info"]:

            creation = result[
                "info"
            ][key]

            break

    for key in modification_keys:

        if key in result["info"]:

            modified = result[
                "info"
            ][key]

            break

    if creation and modified:

        if creation != modified:

            result["warnings"].append(
                "CreationDate و ModDate مختلفان."
            )

            result["score"] += 10

    # --------------------------------------------------------
    # XMP fields
    # --------------------------------------------------------

    xmp = result["xmp"]

    xmp_creator = re.findall(
        r"<(?:[^:>]+:)?CreatorTool[^>]*>"
        r"(.*?)"
        r"</(?:[^:>]+:)?CreatorTool>",
        xmp,
        re.I | re.S,
    )

    xmp_producer = re.findall(
        r"<(?:[^:>]+:)?Producer[^>]*>"
        r"(.*?)"
        r"</(?:[^:>]+:)?Producer>",
        xmp,
        re.I | re.S,
    )

    if xmp_creator:

        creator_text = " ".join(
            xmp_creator
        )

        editors = find_editors(
            creator_text
        )

        if editors:

            result["warnings"].append(
                "XMP CreatorTool: "
                + ", ".join(editors)
            )

            result["score"] += 20

    if xmp_producer:

        producer_text = " ".join(
            xmp_producer
        )

        editors = find_editors(
            producer_text
        )

        if editors:

            result["warnings"].append(
                "XMP Producer: "
                + ", ".join(editors)
            )

            result["score"] += 20

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# DOCUMENT STRUCTURE
# ============================================================

def document_forensics(path):

    result = {
        "pages": 0,
        "text_pages": 0,
        "scan_pages": 0,
        "fonts": set(),
        "images": 0,
        "annotations": 0,
        "forms": False,
        "page_details": [],
        "warnings": [],
        "score": 0,
    }

    doc = None

    try:

        doc = fitz.open(str(path))

        result["pages"] = doc.page_count

        pages = min(
            doc.page_count,
            MAX_PAGES,
        )

        for index in range(pages):

            page = doc[index]

            text = (
                page.get_text("text")
                or ""
            ).strip()

            if len(text) >= 10:

                result[
                    "text_pages"
                ] += 1

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

            if (
                len(text) < 10
                and images
            ):

                result[
                    "scan_pages"
                ] += 1

            fonts = set()

            try:

                for font in page.get_fonts(
                    full=True
                ):

                    if len(font) > 3:

                        name = clean(
                            font[3]
                        )

                        if name:
                            fonts.add(name)
                            result[
                                "fonts"
                            ].add(name)

            except Exception:
                pass

            annot_count = 0

            try:

                annots = page.annots()

                if annots:

                    for _ in annots:
                        annot_count += 1
                        result[
                            "annotations"
                        ] += 1

            except Exception:
                pass

            result[
                "page_details"
            ].append({
                "page": index + 1,
                "text_length": len(text),
                "images": len(images),
                "fonts": sorted(fonts),
                "annotations": annot_count,
            })

        # Forms
        try:

            widgets = []

            for page in doc:

                try:

                    for widget in (
                        page.widgets()
                        or []
                    ):

                        widgets.append(widget)

                except Exception:
                    pass

            if widgets:

                result["forms"] = True

                result["warnings"].append(
                    "AcroForm fields موجودة."
                )

                result["score"] += 3

        except Exception:
            pass

        doc.close()

    except Exception as e:

        logger.warning(
            "Document analysis failed: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    # --------------------------------------------------------
    # Font consistency
    # --------------------------------------------------------

    if len(result["fonts"]) > 12:

        result["warnings"].append(
            f"عدد الخطوط مرتفع: "
            f"{len(result['fonts'])}"
        )

        result["score"] += 5

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# VISUAL PAGE FINGERPRINT
# ============================================================

def visual_forensics(path):

    result = {
        "rendered": 0,
        "hashes": [],
        "error": None,
    }

    doc = None

    try:

        doc = fitz.open(str(path))

        pages = min(
            doc.page_count,
            MAX_PAGES,
        )

        for index in range(pages):

            page = doc[index]

            pix = page.get_pixmap(
                matrix=fitz.Matrix(
                    1.2,
                    1.2,
                ),
                alpha=False,
            )

            digest = hashlib.sha256(
                pix.samples
            ).hexdigest()

            result[
                "hashes"
            ].append(
                digest
            )

            result["rendered"] += 1

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
# FULL ANALYSIS
# ============================================================

def analyze_pdf(path):

    logger.info(
        "🔬 Starting PDF forensic analysis"
    )

    raw = raw_forensics(path)

    metadata = metadata_forensics(
        path
    )

    document = document_forensics(
        path
    )

    visual = visual_forensics(
        path
    )

    # --------------------------------------------------------
    # Combined score
    # --------------------------------------------------------

    score = (
        raw["score"] * 0.40
        + metadata["score"] * 0.40
        + document["score"] * 0.20
    )

    score = round(
        min(100, score)
    )

    warnings = []

    for source in (
        raw,
        metadata,
        document,
    ):

        for warning in source[
            "warnings"
        ]:

            if warning not in warnings:

                warnings.append(
                    warning
                )

    editors = list(
        dict.fromkeys(
            raw["editors"]
            + metadata["editors"]
        )
    )

    if editors:

        score = max(
            score,
            70,
        )

    return {
        "score": score,
        "editors": editors,
        "raw": raw,
        "metadata": metadata,
        "document": document,
        "visual": visual,
        "warnings": warnings,
    }


# ============================================================
# REPORT
# ============================================================

def make_report(
    filename,
    path,
    result,
):

    score = result["score"]

    if score >= 70:

        status = (
            "🔴 تم العثور على مؤشرات قوية "
            "لإعادة معالجة/تعديل الملف"
        )

    elif score >= 40:

        status = (
            "🟠 توجد مؤشرات تستحق الفحص"
        )

    else:

        status = (
            "🟢 لم يتم العثور على مؤشرات قوية"
        )

    raw = result["raw"]
    metadata = result["metadata"]
    document = result["document"]
    visual = result["visual"]

    info = metadata["info"]

    producer = (
        info.get("/Producer")
        or info.get("Producer")
        or "غير موجود"
    )

    creator = (
        info.get("/Creator")
        or info.get("Creator")
        or "غير موجود"
    )

    creation = (
        info.get("/CreationDate")
        or info.get("CreationDate")
        or "غير موجود"
    )

    modified = (
        info.get("/ModDate")
        or info.get("ModDate")
        or "غير موجود"
    )

    size_mb = (
        path.stat().st_size
        / 1024
        / 1024
    )

    lines = [

        "🔎 LEX PDF FORENSIC PRO",

        "",

        f"📄 الملف: {filename}",
        f"📦 الحجم: {size_mb:.2f} MB",
        f"📑 الصفحات: {document['pages']}",

        "",

        status,
        f"📊 Risk Score: {score}/100",

        "",
        "🧪 PDF FORENSICS",

        f"• %%EOF: {raw['eof']}",
        f"• startxref: {raw['startxref']}",
        f"• Objects: {raw['objects']}",
        f"• Streams: {raw['streams']}",

        f"• Incremental revisions: "
        f"{'YES' if raw['eof'] > 1 else 'NO'}",

        f"• JavaScript: "
        f"{'YES' if raw['javascript'] else 'NO'}",

        f"• Embedded files: "
        f"{'YES' if raw['embedded'] else 'NO'}",

        f"• Digital signature indicator: "
        f"{'YES' if raw['signatures'] else 'NO'}",

        "",
        "🛠️ برامج ظهرت في الملف",

    ]

    if result["editors"]:

        for editor in result[
            "editors"
        ]:

            lines.append(
                f"🔴 {editor}"
            )

    else:

        lines.append(
            "🟢 لم يتم العثور على محرر معروف"
        )

    lines += [

        "",
        "📝 PDF INFO",

        f"• Producer: {producer}",
        f"• Creator: {creator}",
        f"• CreationDate: {creation}",
        f"• ModDate: {modified}",

        "",
        "📄 DOCUMENT",

        f"• Text pages: "
        f"{document['text_pages']}",

        f"• Scan pages: "
        f"{document['scan_pages']}",

        f"• Images: "
        f"{document['images']}",

        f"• Fonts: "
        f"{len(document['fonts'])}",

        f"• Annotations: "
        f"{document['annotations']}",

        "",
        "🖼️ VISUAL",

        f"• Rendered: "
        f"{visual['rendered']}",

    ]

    if result["warnings"]:

        lines += [
            "",
            "⚠️ المؤشرات المكتشفة:",
        ]

        for warning in result[
            "warnings"
        ][:20]:

            lines.append(
                "• " + warning[:250]
            )

    lines += [

        "",
        "🔐 SHA-256",

        sha256(path),

        "",
        "⚠️ ملاحظة مهمة:",
        "وجود Sejda أو أي محرر PDF يعني أن "
        "الملف تمت معالجته/إعادة حفظه، "
        "ولا يعني وحده أن المحتوى مزور.",

        "",
        "الفحص بدون النسخة الأصلية لا يستطيع "
        "إثبات أن قيمة أو اسمًا معينًا تم تغييره.",

        "",
        "By LEX",
    ]

    return "\n".join(lines)


# ============================================================
# /START
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    await update.message.reply_text(
        "🤖 LEX PDF FORENSIC PRO\n\n"
        "ابعث PDF وأنا نفحص:\n\n"
        "🔎 PDF structure\n"
        "🛠️ Sejda / Adobe / Smallpdf وغيرها\n"
        "📝 Info + XMP metadata\n"
        "🔄 revisions / xref / EOF\n"
        "📦 PDF objects\n"
        "🔤 fonts\n"
        "🖼️ images / rendering\n\n"
        "⚠️ النتيجة مؤشرات تقنية وليست "
        "إثباتًا قانونيًا للتزوير."
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

    size = document.file_size or 0

    if size > MAX_FILE_SIZE:

        await update.message.reply_text(
            f"❌ الملف كبير.\n"
            f"الحد الأقصى {MAX_FILE_MB} MB."
        )

        return

    workdir = Path(
        tempfile.mkdtemp(
            prefix="lex_pdf_"
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
            "🔍 استلمت الملف.\n\n"
            "جاري الفحص الجنائي للـPDF..."
        )

        tg_file = (
            await document.get_file()
        )

        await tg_file.download_to_drive(
            custom_path=str(path)
        )

        if not path.exists():
            raise RuntimeError(
                "PDF download failed"
            )

        with open(
            path,
            "rb",
        ) as f:

            header = f.read(8)

        if not header.startswith(
            b"%PDF"
        ):

            await update.message.reply_text(
                "❌ الملف ليس PDF صالحًا."
            )

            return

        result = await asyncio.to_thread(
            analyze_pdf,
            path,
        )

        report = make_report(
            filename,
            path,
            result,
        )

        # Telegram max message size safety
        if len(report) > 3900:

            report = (
                report[:3800]
                + "\n\n…"
            )

        await update.message.reply_text(
            report
        )

        logger.info(
            "✅ PDF analyzed | %s | score=%s",
            filename,
            result["score"],
        )

    except Exception as e:

        logger.exception(
            "PDF analysis failed: %s",
            e,
        )

        try:

            await update.message.reply_text(
                "❌ حدث خطأ أثناء التحليل.\n"
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
            "Telegram rate limit: %s sec",
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
        "🚀 LEX PDF FORENSIC PRO"
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
