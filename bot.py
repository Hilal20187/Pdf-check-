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

MAX_FILE_MB = 25
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
# KNOWN EXTERNAL EDITORS
# ============================================================

KNOWN_EDITORS = {
    "sejda": "Sejda",
    "smallpdf": "Smallpdf",
    "ilovepdf": "iLovePDF",
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
    "master pdf editor": "Master PDF Editor",
    "pdftk": "PDFtk",
}


# ============================================================
# HELPERS
# ============================================================

def text(value):
    if value is None:
        return ""
    return str(value).strip()


def find_editors(data):

    data = data.lower()

    found = []

    for key, name in KNOWN_EDITORS.items():

        if key.lower() in data:

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
# RAW PDF ANALYSIS
# ============================================================

def analyze_raw(path):

    raw = path.read_bytes()

    try:
        raw_text = raw.decode(
            "latin-1",
            errors="ignore",
        )
    except Exception:
        raw_text = ""

    result = {
        "eof": len(
            re.findall(
                rb"%%EOF",
                raw,
            )
        ),
        "startxref": len(
            re.findall(
                rb"startxref",
                raw,
            )
        ),
        "xref": len(
            re.findall(
                rb"(?:^|\n)xref(?:\s|\n)",
                raw,
                re.MULTILINE,
            )
        ),
        "objects": len(
            re.findall(
                rb"\n\d+\s+\d+\s+obj\b",
                raw,
            )
        ),
        "streams": len(
            re.findall(
                rb"\bstream\b",
                raw,
            )
        ),
        "editors": find_editors(
            raw_text
        ),
        "javascript": False,
        "embedded": False,
        "signature": False,
        "score": 0,
        "evidence": [],
    }

    # --------------------------------------------------------
    # External editor fingerprints
    # --------------------------------------------------------

    if result["editors"]:

        for editor in result["editors"]:

            result["evidence"].append(
                f"وجدت بصمة برنامج خارجي: {editor}"
            )

        # Strong signal that PDF was processed.
        result["score"] += 45

    # --------------------------------------------------------
    # Incremental revisions
    # --------------------------------------------------------

    if result["eof"] > 1:

        result["evidence"].append(
            f"الملف يحتوي على {result['eof']} %%EOF؛ "
            "هذا قد يشير إلى عدة revisions."
        )

        result["score"] += min(
            20,
            (result["eof"] - 1) * 5,
        )

    if result["startxref"] > 1:

        result["evidence"].append(
            f"تم العثور على {result['startxref']} startxref."
        )

        result["score"] += 5

    # --------------------------------------------------------
    # JavaScript
    # --------------------------------------------------------

    if (
        b"/JavaScript" in raw
        or b"/JS " in raw
        or b"/JS/" in raw
    ):

        result["javascript"] = True

        result["evidence"].append(
            "JavaScript موجود داخل PDF."
        )

        result["score"] += 15

    # --------------------------------------------------------
    # Embedded files
    # --------------------------------------------------------

    if (
        b"/EmbeddedFile" in raw
        or b"/Filespec" in raw
    ):

        result["embedded"] = True

        result["evidence"].append(
            "يوجد embedded file/object."
        )

        result["score"] += 3

    # --------------------------------------------------------
    # Digital signature indicator
    # --------------------------------------------------------

    if (
        b"/ByteRange" in raw
        or b"/adbe.pkcs7" in raw
        or b"/Adobe.PPKLite" in raw
    ):

        result["signature"] = True

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# METADATA / XMP
# ============================================================

def analyze_metadata(path):

    result = {
        "info": {},
        "xmp": "",
        "editors": [],
        "score": 0,
        "evidence": [],
    }

    # --------------------------------------------------------
    # PDF Info
    # --------------------------------------------------------

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        if reader.metadata:

            for key, value in reader.metadata.items():

                key = text(key)
                value = text(value)

                if key and value:

                    result["info"][key] = value

    except Exception as e:

        logger.warning(
            "Info metadata error: %s",
            e,
        )

    # --------------------------------------------------------
    # XMP
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
            "XMP error: %s",
            e,
        )

    # --------------------------------------------------------
    # Search external applications
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

            result["evidence"].append(
                f"Metadata/XMP يحتوي على: {editor}"
            )

        result["score"] += 50

    # --------------------------------------------------------
    # Dates
    # --------------------------------------------------------

    creation = ""

    modified = ""

    for key in (
        "/CreationDate",
        "CreationDate",
        "creationDate",
    ):

        if key in result["info"]:

            creation = result[
                "info"
            ][key]

            break

    for key in (
        "/ModDate",
        "ModDate",
        "modDate",
    ):

        if key in result["info"]:

            modified = result[
                "info"
            ][key]

            break

    if creation and modified:

        if creation != modified:

            result["evidence"].append(
                "CreationDate مختلف عن ModDate."
            )

            result["score"] += 10

    # --------------------------------------------------------
    # XMP CreatorTool
    # --------------------------------------------------------

    xmp = result["xmp"]

    creator_matches = re.findall(
        r"<(?:[^:>]+:)?CreatorTool[^>]*>"
        r"(.*?)"
        r"</(?:[^:>]+:)?CreatorTool>",
        xmp,
        re.I | re.S,
    )

    if creator_matches:

        creator = " ".join(
            creator_matches
        )

        editors = find_editors(
            creator
        )

        for editor in editors:

            result["evidence"].append(
                f"XMP CreatorTool: {editor}"
            )

            result["score"] += 20

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# PAGE / FONT / IMAGE ANALYSIS
# ============================================================

def analyze_document(path):

    result = {
        "pages": 0,
        "text_pages": 0,
        "scan_pages": 0,
        "images": 0,
        "annotations": 0,
        "fonts": set(),
        "font_by_page": {},
        "score": 0,
        "evidence": [],
    }

    doc = None

    try:

        doc = fitz.open(str(path))

        result["pages"] = doc.page_count

        pages = min(
            doc.page_count,
            MAX_PAGES,
        )

        for i in range(pages):

            page = doc[i]

            page_number = i + 1

            extracted = (
                page.get_text("text")
                or ""
            ).strip()

            if len(extracted) >= 10:

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
                len(extracted) < 10
                and images
            ):

                result[
                    "scan_pages"
                ] += 1

            page_fonts = set()

            try:

                for font in page.get_fonts(
                    full=True
                ):

                    if len(font) > 3:

                        name = text(
                            font[3]
                        )

                        if name:

                            page_fonts.add(
                                name
                            )

                            result[
                                "fonts"
                            ].add(name)

            except Exception:
                pass

            result[
                "font_by_page"
            ][page_number] = page_fonts

            try:

                annots = page.annots()

                if annots:

                    for _ in annots:

                        result[
                            "annotations"
                        ] += 1

            except Exception:
                pass

        doc.close()

    except Exception as e:

        logger.warning(
            "Document analysis error: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    # --------------------------------------------------------
    # Font inconsistency
    # --------------------------------------------------------

    page_font_sets = [
        fonts
        for fonts in result[
            "font_by_page"
        ].values()
        if fonts
    ]

    if len(result["fonts"]) >= 10:

        result["evidence"].append(
            f"عدد الخطوط المختلفـة مرتفع: "
            f"{len(result['fonts'])}"
        )

        result["score"] += 5

    # Look for a font appearing on only one page.
    if len(page_font_sets) >= 2:

        frequency = {}

        for fonts in page_font_sets:

            for font in fonts:

                frequency[font] = (
                    frequency.get(font, 0)
                    + 1
                )

        rare_fonts = [
            font
            for font, count
            in frequency.items()
            if count == 1
        ]

        if rare_fonts:

            result["evidence"].append(
                "وجدت خطوطًا تظهر في صفحة واحدة فقط."
            )

            result["score"] += min(
                8,
                len(rare_fonts) * 2,
            )

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# VISUAL RENDER
# ============================================================

def visual_analysis(path):

    result = {
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

        for i in range(pages):

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
# MAIN FORENSIC ENGINE
# ============================================================

def forensic_scan(path):

    raw = analyze_raw(path)

    metadata = analyze_metadata(
        path
    )

    document = analyze_document(
        path
    )

    visual = visual_analysis(
        path
    )

    evidence = []

    for source in (
        raw,
        metadata,
        document,
    ):

        for item in source[
            "evidence"
        ]:

            if item not in evidence:

                evidence.append(item)

    editors = list(
        dict.fromkeys(
            raw["editors"]
            + metadata["editors"]
        )
    )

    # --------------------------------------------------------
    # Weighted score
    # --------------------------------------------------------

    score = (
        raw["score"] * 0.45
        + metadata["score"] * 0.40
        + document["score"] * 0.15
    )

    score = round(
        min(100, score)
    )

    # Known editor is a particularly strong
    # "processed by external software" signal.
    if editors:

        score = max(
            score,
            80,
        )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if editors:

        status = (
            "🔴 احتمال كبير للتعديل"
        )

    elif score >= 65:

        status = (
            "🔴 مؤشرات قوية على التعديل"
        )

    elif score >= 35:

        status = (
            "🟠 احتمال وجود تعديل"
        )

    else:

        status = (
            "🟢 لا توجد مؤشرات قوية"
        )

    return {
        "score": score,
        "status": status,
        "editors": editors,
        "evidence": evidence,
        "raw": raw,
        "metadata": metadata,
        "document": document,
        "visual": visual,
    }


# ============================================================
# REPORT
# ============================================================

def make_report(
    filename,
    path,
    result,
):

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
        f"📄 {filename}",
        f"📦 الحجم: {size_mb:.2f} MB",
        f"📑 الصفحات: {document['pages']}",

        "",
        result["status"],
        f"📊 Risk Score: {result['score']}/100",

        "",
        "🛠️ المصدر / البرامج",

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
            "🟢 لم يتم العثور على بصمة محرر معروف"
        )

    lines += [

        "",
        "📝 PDF Metadata",

        f"• Producer: {producer}",
        f"• Creator: {creator}",
        f"• CreationDate: {creation}",
        f"• ModDate: {modified}",

        "",
        "🔬 Structure",

        f"• Objects: {raw['objects']}",
        f"• Streams: {raw['streams']}",
        f"• xref: {raw['xref']}",
        f"• startxref: {raw['startxref']}",
        f"• %%EOF: {raw['eof']}",

        f"• Incremental revisions: "
        f"{'YES' if raw['eof'] > 1 else 'NO'}",

        f"• JavaScript: "
        f"{'YES' if raw['javascript'] else 'NO'}",

        f"• Embedded files: "
        f"{'YES' if raw['embedded'] else 'NO'}",

        f"• Signature indicator: "
        f"{'YES' if raw['signature'] else 'NO'}",

        "",
        "📄 Content",

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
        "⚠️ Evidence",
    ]

    if result["evidence"]:

        for evidence in result[
            "evidence"
        ][:15]:

            lines.append(
                "• " + evidence[:240]
            )

    else:

        lines.append(
            "• لم يتم العثور على مؤشرات قوية."
        )

    lines += [

        "",
        "🔐 SHA-256",
        sha256(path),

        "",
        "⚠️ ملاحظة:",
        "هذا النظام يكشف آثار المعالجة "
        "والتعديل التقني. بدون النسخة الأصلية "
        "لا يمكن إثبات أن معلومة معينة "
        "تم تغييرها بنسبة 100%.",

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
        "ابعث PDF للتحليل.\n\n"
        "🔎 أبحث عن آثار Sejda وSmallpdf "
        "وAdobe وغيرها\n"
        "📝 PDF Info + XMP\n"
        "🔄 revisions / xref / EOF\n"
        "📦 objects / streams\n"
        "🔤 fonts\n"
        "🖼️ rendering\n\n"
        "⚠️ النتيجة تقنية وليست إثباتًا "
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

    size = document.file_size or 0

    if size > MAX_FILE_SIZE:

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
            "جاري التحليل الجنائي..."
        )

        tg_file = (
            await document.get_file()
        )

        await tg_file.download_to_drive(
            custom_path=str(path)
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
            forensic_scan,
            path,
        )

        report = make_report(
            filename,
            path,
            result,
        )

        if len(report) > 3900:

            report = (
                report[:3800]
                + "\n\n..."
            )

        await update.message.reply_text(
            report
        )

        logger.info(
            "Analysis complete | score=%s | editors=%s",
            result["score"],
            result["editors"],
        )

    except Exception as e:

        logger.exception(
            "PDF analysis failed: %s",
            e,
        )

        try:

            await update.message.reply_text(
                "❌ حدث خطأ أثناء تحليل الملف."
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
            "🚨 409 CONFLICT: "
            "another instance is using BOT_TOKEN"
        )

        return

    if isinstance(
        error,
        RetryAfter,
    ):

        logger.warning(
            "Rate limited: %s",
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
# RUN
# ============================================================

def main():

    if not BOT_TOKEN:

        raise RuntimeError(
            "BOT_TOKEN missing"
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
        "🚀 LEX PDF FORENSIC PRO READY"
    )

    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main() 
