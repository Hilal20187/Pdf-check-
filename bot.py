import os
import re
import hashlib
import logging
import tempfile
import shutil
import asyncio
import mimetypes
from pathlib import Path
from datetime import datetime

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | LEX | %(message)s",
)

logger = logging.getLogger("LEX")


# ============================================================
# KNOWN SOFTWARE / EDITORS
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

def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def find_editors(data):
    data = data.lower()
    found = []

    for key, name in KNOWN_EDITORS.items():
        if key.lower() in data and name not in found:
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
# MIME TYPE
# ============================================================

def get_mime_type(path):
    """
    Detect MIME without trusting .pdf extension.

    Uses:
    1. Python mimetypes
    2. Linux 'file' command if available
    3. PDF magic header
    """

    extension_mime = (
        mimetypes.guess_type(
            str(path)
        )[0]
        or "unknown"
    )

    command_mime = "unavailable"

    try:
        import subprocess

        output = subprocess.check_output(
            [
                "file",
                "--brief",
                "--mime-type",
                str(path),
            ],
            stderr=subprocess.DEVNULL,
            timeout=5,
        )

        command_mime = (
            output
            .decode(
                "utf-8",
                errors="ignore",
            )
            .strip()
        )

    except Exception:
        pass

    try:

        with open(
            path,
            "rb",
        ) as f:

            header = f.read(8)

    except Exception:

        header = b""

    magic_mime = (
        "application/pdf"
        if header.startswith(b"%PDF")
        else "unknown"
    )

    return {
        "extension": extension_mime,
        "file_command": command_mime,
        "magic": magic_mime,
    }


# ============================================================
# PDF DATE PARSER
# ============================================================

def parse_pdf_date(value):

    if not value:
        return None

    value = clean(value)

    if value.startswith("D:"):
        value = value[2:]

    match = re.match(
        r"^(\d{4})"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(?:(\d{2}))?"
        r"(Z|[+-]\d{2}'?\d{2}'?)?$",
        value,
    )

    if not match:
        return None

    try:

        year = int(match.group(1))
        month = int(match.group(2) or 1)
        day = int(match.group(3) or 1)
        hour = int(match.group(4) or 0)
        minute = int(match.group(5) or 0)
        second = int(match.group(6) or 0)

        return datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
        )

    except Exception:

        return None


# ============================================================
# METADATA DATE EXTRACTION
# ============================================================

def get_metadata_value(info, names):

    for name in names:

        if name in info:
            return clean(info[name])

    return ""


# ============================================================
# RAW FORENSICS
# ============================================================

def analyze_raw(path):

    raw = path.read_bytes()

    raw_text = raw.decode(
        "latin-1",
        errors="ignore",
    )

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

    # External editors

    if result["editors"]:

        for editor in result["editors"]:

            result["evidence"].append(
                f"🔴 بصمة برنامج خارجي: {editor}"
            )

        result["score"] += 50

    # Multiple EOF

    if result["eof"] > 1:

        result["evidence"].append(
            f"تم العثور على {result['eof']} %%EOF."
        )

        result["score"] += min(
            25,
            (result["eof"] - 1) * 5,
        )

    # JavaScript

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

    # Embedded files

    if (
        b"/EmbeddedFile" in raw
        or b"/Filespec" in raw
    ):

        result["embedded"] = True

        result["evidence"].append(
            "يوجد Embedded File/Object."
        )

        result["score"] += 3

    # Signature indicator

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
# METADATA FORENSICS
# ============================================================

def analyze_metadata(path):

    result = {

        "info": {},
        "xmp": "",

        "editors": [],

        "creation_raw": "",
        "modified_raw": "",

        "create_date_raw": "",
        "modify_date_raw": "",

        "creation_date": None,
        "modified_date": None,

        "date_difference": False,
        "difference_seconds": None,

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

                key = clean(key)
                value = clean(value)

                if key and value:
                    result["info"][key] = value

    except Exception as e:

        logger.warning(
            "Metadata error: %s",
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

    info = result["info"]

    # --------------------------------------------------------
    # Creation / Create Date
    # --------------------------------------------------------

    result["creation_raw"] = get_metadata_value(
        info,
        [
            "/CreationDate",
            "CreationDate",
            "creationDate",
            "CreateDate",
            "Create Date",
            "Creation Date",
        ],
    )

    result["create_date_raw"] = get_metadata_value(
        info,
        [
            "CreateDate",
            "Create Date",
        ],
    )

    # --------------------------------------------------------
    # Modification / Modify Date
    # --------------------------------------------------------

    result["modified_raw"] = get_metadata_value(
        info,
        [
            "/ModDate",
            "ModDate",
            "modDate",
            "ModifyDate",
            "Modify Date",
            "ModificationDate",
            "Modification Date",
        ],
    )

    result["modify_date_raw"] = get_metadata_value(
        info,
        [
            "ModifyDate",
            "Modify Date",
            "ModificationDate",
            "Modification Date",
        ],
    )

    # --------------------------------------------------------
    # Parse dates
    # --------------------------------------------------------

    result["creation_date"] = parse_pdf_date(
        result["creation_raw"]
    )

    result["modified_date"] = parse_pdf_date(
        result["modified_raw"]
    )

    # ========================================================
    # STRICT DATE RULE
    # ========================================================

    if (
        result["creation_date"]
        and result["modified_date"]
    ):

        difference = (
            result["modified_date"]
            - result["creation_date"]
        )

        result["difference_seconds"] = abs(
            difference.total_seconds()
        )

        if (
            result["creation_date"]
            != result["modified_date"]
        ):

            result["date_difference"] = True

            result["score"] = 100

            result["evidence"].append(
                "🔴 CreationDate و ModDate مختلفان."
            )

            result["evidence"].append(
                "🔴 حسب القاعدة الصارمة: "
                "الملف MODIFIED."
            )

            result["evidence"].append(
                f"⏱️ فرق التوقيت: "
                f"{result['difference_seconds']:.0f} ثانية."
            )

    # --------------------------------------------------------
    # External software in metadata
    # --------------------------------------------------------

    info_text = "\n".join(
        f"{k}: {v}"
        for k, v in info.items()
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
                f"🔴 Metadata/XMP: {editor}"
            )

        result["score"] = max(
            result["score"],
            90,
        )

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# DOCUMENT ANALYSIS
# ============================================================

def analyze_document(path):

    result = {

        "pages": 0,
        "text_pages": 0,
        "scan_pages": 0,
        "images": 0,
        "annotations": 0,

        "fonts": set(),

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

            page_text = (
                page.get_text("text")
                or ""
            ).strip()

            if len(page_text) >= 10:
                result["text_pages"] += 1

            try:

                images = page.get_images(
                    full=True
                )

                result["images"] += len(
                    images
                )

            except Exception:

                images = []

            if (
                len(page_text) < 10
                and images
            ):

                result["scan_pages"] += 1

            try:

                for font in page.get_fonts(
                    full=True
                ):

                    if len(font) > 3:

                        name = clean(
                            font[3]
                        )

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

    if len(result["fonts"]) >= 10:

        result["score"] += 5

        result["evidence"].append(
            f"عدد الخطوط مرتفع: "
            f"{len(result['fonts'])}"
        )

    result["score"] = min(
        100,
        result["score"],
    )

    return result


# ============================================================
# FORENSIC ENGINE
# ============================================================

def forensic_scan(path):

    raw = analyze_raw(path)

    metadata = analyze_metadata(
        path
    )

    document = analyze_document(
        path
    )

    mime = get_mime_type(
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

    # ========================================================
    # MIME CHECK
    # ========================================================

    mime_problem = False

    if (
        mime["magic"]
        != "application/pdf"
    ):

        mime_problem = True

        evidence.append(
            "🔴 الملف لا يحمل PDF magic header صالحًا."
        )

    if (
        mime["file_command"]
        not in (
            "unavailable",
            "",
            "application/pdf",
        )
    ):

        mime_problem = True

        evidence.append(
            "🟠 MIME الحقيقي مختلف عن application/pdf: "
            + mime["file_command"]
        )

    # ========================================================
    # FINAL CLASSIFICATION
    # ========================================================

    # STRICT DATE RULE
    if metadata["date_difference"]:

        score = 100

        status = (
            "🔴 MODIFIED — غير مطابق"
        )

    elif editors:

        score = 90

        status = (
            "🔴 تمت معالجة الملف ببرنامج خارجي"
        )

    elif mime_problem:

        score = 80

        status = (
            "🔴 MIME / FILE TYPE مشبوه"
        )

    else:

        score = round(
            raw["score"] * 0.50
            + metadata["score"] * 0.35
            + document["score"] * 0.15
        )

        if score >= 65:

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
        "mime": mime,
    }


# ============================================================
# REPORT
# ============================================================

def make_report(
    filename,
    path,
    result,
):

    metadata = result["metadata"]
    raw = result["raw"]
    document = result["document"]
    mime = result["mime"]

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
        metadata["creation_raw"]
        or "غير موجود"
    )

    modified = (
        metadata["modified_raw"]
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
        "📝 PDF DATES",

        f"• CreationDate: {creation}",
        f"• ModDate: {modified}",

    ]

    # --------------------------------------------------------
    # Date warning
    # --------------------------------------------------------

    if metadata["date_difference"]:

        lines += [

            "",
            "🚨 DATE ALERT",

            "🔴 CreationDate ≠ ModDate",

            f"⏱️ الفرق: "
            f"{metadata['difference_seconds']:.0f} ثانية",

            "🔴 حسب النظام الصارم:",
            "MODIFIED / غير مطابق",

        ]

    lines += [

        "",
        "📅 Other date fields",

        f"• Create Date: "
        f"{metadata['create_date_raw'] or 'غير موجود'}",

        f"• Modify Date: "
        f"{metadata['modify_date_raw'] or 'غير موجود'}",

        "",
        "🛠️ SOURCE / SOFTWARE",

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
            "🟢 لا توجد بصمة محرر معروف"
        )

    lines += [

        "",
        "🌐 MIME TYPE",

        f"• Extension MIME: "
        f"{mime['extension']}",

        f"• Real MIME: "
        f"{mime['file_command']}",

        f"• Magic Header: "
        f"{mime['magic']}",

        "",
        "📝 PDF Metadata",

        f"• Producer: {producer}",
        f"• Creator: {creator}",

        "",
        "🔬 PDF Structure",

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
        "📄 CONTENT",

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
        "⚠️ EVIDENCE",
    ]

    if result["evidence"]:

        for item in result[
            "evidence"
        ][:20]:

            lines.append(
                "• " + item[:250]
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
        "⚠️ تنبيه:",
        "هذا فحص تقني للملف وليس إثباتًا "
        "قانونيًا للتزوير. اختلاف CreationDate "
        "وModDate يعني وجود اختلاف في بيانات "
        "التاريخ، وقد ينتج عن إعادة حفظ الملف "
        "دون تغيير محتواه.",

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
        "ابعث PDF للتحليل.\n\n"
        "🔴 CreationDate / ModDate\n"
        "🔴 Create Date / Modify Date\n"
        "🔎 MIME الحقيقي\n"
        "🛠️ Sejda / Adobe / Smallpdf\n"
        "📝 PDF Metadata + XMP\n"
        "🔄 PDF revisions\n"
        "🔬 Objects / Fonts / Images"
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
            "🔍 استلمت الملف.\n"
            "جاري الفحص الجنائي..."
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
                "❌ الملف لا يحتوي على PDF header صالح."
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
            "Analysis complete | score=%s",
            result["score"],
        )

    except Exception:

        logger.exception(
            "PDF analysis failed"
        )

        try:

            await update.message.reply_text(
                "❌ حدث خطأ أثناء تحليل PDF."
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
            "🚨 409 CONFLICT — "
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
        "Telegram error"
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
        "🚀 LEX PDF FORENSIC PRO STARTING"
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
        "✅ BOT READY"
    )

    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES,
    )


if __name__ == "__main__":
    main() 
