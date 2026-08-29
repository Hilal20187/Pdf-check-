import os
import re
import json
import math
import hashlib
import logging
import tempfile
import shutil
import asyncio
import mimetypes
import subprocess
from pathlib import Path
from datetime import datetime

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

MAX_FILE_MB = 25
MAX_FILE_SIZE = MAX_FILE_MB * 1024 * 1024
MAX_PAGES = 100

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | LEX | %(message)s",
)

logger = logging.getLogger("LEX")


# ============================================================
# KNOWN PDF SOFTWARE
# ============================================================

SOFTWARE_SIGNATURES = {
    "sejda": "Sejda",
    "smallpdf": "Smallpdf",
    "ilovepdf": "iLovePDF",
    "pdfescape": "PDFescape",
    "pdfsam": "PDFsam",
    "nitro": "Nitro PDF",
    "foxit": "Foxit PDF",
    "adobe acrobat": "Adobe Acrobat",
    "acrobat": "Adobe Acrobat",
    "photoshop": "Adobe Photoshop",
    "illustrator": "Adobe Illustrator",
    "indesign": "Adobe InDesign",
    "canva": "Canva",
    "libreoffice": "LibreOffice",
    "master pdf editor": "Master PDF Editor",
    "pdftk": "PDFtk",
    "wkhtmltopdf": "wkhtmltopdf",
    "ghostscript": "Ghostscript",
}


# ============================================================
# HELPERS
# ============================================================

def clean(value):
    return "" if value is None else str(value).strip()


def sha256(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def unique(items):
    return list(dict.fromkeys(items))


def find_signatures(text):
    text = text.lower()
    found = []

    for signature, name in SOFTWARE_SIGNATURES.items():
        if signature in text:
            found.append(name)

    return unique(found)


# ============================================================
# MIME FORENSICS
# ============================================================

def mime_forensics(path):

    extension_mime = (
        mimetypes.guess_type(str(path))[0]
        or "unknown"
    )

    magic = "unknown"
    file_mime = "unavailable"

    try:
        with open(path, "rb") as f:
            header = f.read(16)

        if header.startswith(b"%PDF"):
            magic = "application/pdf"

    except Exception:
        pass

    try:

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

        file_mime = output.decode(
            "utf-8",
            errors="ignore",
        ).strip()

    except Exception:
        pass

    return {
        "extension": extension_mime,
        "magic": magic,
        "file": file_mime,
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
        return datetime(
            int(match.group(1)),
            int(match.group(2) or 1),
            int(match.group(3) or 1),
            int(match.group(4) or 0),
            int(match.group(5) or 0),
            int(match.group(6) or 0),
        )

    except Exception:
        return None


# ============================================================
# PDF METADATA
# ============================================================

def metadata_forensics(path):

    info = {}
    xmp = ""
    evidence = []

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        if reader.metadata:

            for key, value in reader.metadata.items():

                key = clean(key)
                value = clean(value)

                if key:
                    info[key] = value

    except Exception as e:

        logger.warning(
            "pypdf metadata: %s",
            e,
        )

    try:

        doc = fitz.open(str(path))

        try:
            xmp = doc.get_xml_metadata() or ""
        except Exception:
            xmp = ""

        doc.close()

    except Exception as e:

        logger.warning(
            "XMP: %s",
            e,
        )

    def get(names):

        for name in names:
            if name in info:
                return clean(info[name])

        return ""

    creation_raw = get(
        [
            "/CreationDate",
            "CreationDate",
        ]
    )

    modified_raw = get(
        [
            "/ModDate",
            "ModDate",
        ]
    )

    create_raw = get(
        [
            "CreateDate",
            "Create Date",
        ]
    )

    modify_raw = get(
        [
            "ModifyDate",
            "Modify Date",
            "ModificationDate",
            "Modification Date",
        ]
    )

    creation = parse_pdf_date(
        creation_raw
    )

    modified = parse_pdf_date(
        modified_raw
    )

    create_xmp = parse_pdf_date(
        create_raw
    )

    modify_xmp = parse_pdf_date(
        modify_raw
    )

    date_differences = []

    # PDF CreationDate vs ModDate
    if creation and modified:

        if creation != modified:

            date_differences.append(
                "CreationDate ≠ ModDate"
            )

    # XMP CreateDate vs ModifyDate
    if create_xmp and modify_xmp:

        if create_xmp != modify_xmp:

            date_differences.append(
                "XMP CreateDate ≠ ModifyDate"
            )

    # PDF dates vs XMP dates
    if creation and create_xmp:

        if creation != create_xmp:

            date_differences.append(
                "PDF CreationDate ≠ XMP CreateDate"
            )

    if modified and modify_xmp:

        if modified != modify_xmp:

            date_differences.append(
                "PDF ModDate ≠ XMP ModifyDate"
            )

    signatures = find_signatures(
        json.dumps(info)
        + "\n"
        + xmp
    )

    return {
        "info": info,
        "xmp": xmp,
        "creation_raw": creation_raw,
        "modified_raw": modified_raw,
        "create_raw": create_raw,
        "modify_raw": modify_raw,
        "creation": creation,
        "modified": modified,
        "create_xmp": create_xmp,
        "modify_xmp": modify_xmp,
        "date_differences": date_differences,
        "signatures": signatures,
        "evidence": evidence,
    }


# ============================================================
# RAW PDF STRUCTURE
# ============================================================

def structure_forensics(path):

    raw = path.read_bytes()

    text = raw.decode(
        "latin-1",
        errors="ignore",
    )

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

    object_count = len(
        re.findall(
            rb"(?:^|\n)\d+\s+\d+\s+obj\b",
            raw,
            re.MULTILINE,
        )
    )

    stream_count = len(
        re.findall(
            rb"\bstream\b",
            raw,
        )
    )

    prev_count = len(
        re.findall(
            rb"/Prev\b",
            raw,
        )
    )

    xref_count = len(
        re.findall(
            rb"(?:^|\n)xref(?:\s|\n)",
            raw,
            re.MULTILINE,
        )
    )

    byte_range = (
        b"/ByteRange"
        in raw
    )

    javascript = (
        b"/JavaScript" in raw
        or b"/JS " in raw
        or b"/JS/" in raw
    )

    embedded = (
        b"/EmbeddedFile" in raw
        or b"/Filespec" in raw
    )

    forms = (
        b"/AcroForm" in raw
    )

    annotations = (
        b"/Annots" in raw
    )

    signatures = (
        byte_range
        or b"/adbe.pkcs7" in raw
        or b"/Adobe.PPKLite" in raw
    )

    editors = find_signatures(
        text
    )

    evidence = []

    if eof_count > 1:

        evidence.append(
            f"Multiple %%EOF markers: {eof_count}"
        )

    if prev_count > 0:

        evidence.append(
            f"/Prev chain detected: {prev_count}"
        )

    if editors:

        for editor in editors:

            evidence.append(
                f"Software fingerprint: {editor}"
            )

    if javascript:

        evidence.append(
            "JavaScript detected"
        )

    if embedded:

        evidence.append(
            "Embedded file detected"
        )

    return {
        "bytes": len(raw),
        "eof": eof_count,
        "startxref": startxref_count,
        "xref": xref_count,
        "objects": object_count,
        "streams": stream_count,
        "prev": prev_count,
        "byte_range": byte_range,
        "javascript": javascript,
        "embedded": embedded,
        "forms": forms,
        "annotations": annotations,
        "signatures": signatures,
        "editors": editors,
        "evidence": evidence,
    }


# ============================================================
# CONTENT FORENSICS
# ============================================================

def content_forensics(path):

    result = {
        "pages": 0,
        "text_pages": 0,
        "image_pages": 0,
        "images": 0,
        "fonts": set(),
        "font_usage": {},
        "font_page_map": {},
        "annotations": 0,
        "forms": 0,
        "text_blocks": 0,
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

        for page_index in range(pages):

            page = doc[page_index]

            page_number = (
                page_index + 1
            )

            text = (
                page.get_text("text")
                or ""
            ).strip()

            if text:
                result[
                    "text_pages"
                ] += 1

            try:

                blocks = page.get_text(
                    "dict"
                ).get(
                    "blocks",
                    []
                )

                result[
                    "text_blocks"
                ] += len(blocks)

            except Exception:
                pass

            try:

                images = page.get_images(
                    full=True
                )

                count = len(images)

                result[
                    "images"
                ] += count

                if count:
                    result[
                        "image_pages"
                    ] += 1

            except Exception:

                images = []

            page_fonts = set()

            try:

                for font in page.get_fonts(
                    full=True
                ):

                    if len(font) <= 3:
                        continue

                    name = clean(
                        font[3]
                    )

                    if not name:
                        continue

                    page_fonts.add(name)

                    result[
                        "fonts"
                    ].add(name)

                    result[
                        "font_usage"
                    ][name] = (
                        result[
                            "font_usage"
                        ].get(name, 0)
                        + 1
                    )

            except Exception:
                pass

            result[
                "font_page_map"
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

        # AcroForm
        try:

            widgets = []

            for page in doc:

                try:

                    widgets.extend(
                        list(
                            page.widgets()
                            or []
                        )
                    )

                except Exception:
                    pass

            result["forms"] = len(
                widgets
            )

        except Exception:
            pass

        doc.close()

    except Exception as e:

        logger.warning(
            "Content analysis: %s",
            e,
        )

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    # --------------------------------------------------------
    # Font anomalies
    # --------------------------------------------------------

    if len(result["fonts"]) >= 12:

        result["evidence"].append(
            "عدد الخطوط مرتفع بشكل غير معتاد."
        )

    # Font change between pages
    if len(
        result["font_page_map"]
    ) >= 2:

        maps = list(
            result[
                "font_page_map"
            ].values()
        )

        signatures = [
            tuple(sorted(x))
            for x in maps
        ]

        if len(set(signatures)) > 1:

            result["evidence"].append(
                "توجد اختلافات في تركيبة الخطوط بين الصفحات."
            )

    return result


# ============================================================
# OBJECT / CONTENT ANOMALIES
# ============================================================

def advanced_structure(path):

    evidence = []

    try:

        reader = PdfReader(
            str(path),
            strict=False,
        )

        total = len(
            reader.pages
        )

        # Check page object references
        page_objects = []

        for page in reader.pages:

            try:

                page_objects.append(
                    str(page)
                )

            except Exception:
                pass

        if total > 0 and not page_objects:

            evidence.append(
                "Page objects could not be reconstructed."
            )

    except Exception:
        pass

    return evidence


# ============================================================
# SCORE ENGINE
# ============================================================

def calculate_score(
    metadata,
    structure,
    content,
    mime,
    advanced,
):

    score = 0
    reasons = []

    # --------------------------------------------------------
    # 1. Date inconsistencies
    # --------------------------------------------------------

    date_differences = metadata[
        "date_differences"
    ]

    if date_differences:

        # Strong indicator, but not automatic proof.
        score += min(
            40,
            15 * len(date_differences),
        )

        for item in date_differences:

            reasons.append(
                "🔴 " + item
            )

    # --------------------------------------------------------
    # 2. Known editor
    # --------------------------------------------------------

    if metadata["signatures"]:

        score += min(
            30,
            15 * len(
                metadata["signatures"]
            ),
        )

        for editor in metadata[
            "signatures"
        ]:

            reasons.append(
                f"🔴 محرر معروف: {editor}"
            )

    if structure["editors"]:

        for editor in structure[
            "editors"
        ]:

            if editor not in metadata[
                "signatures"
            ]:

                score += 20

                reasons.append(
                    f"🔴 بصمة برنامج داخل PDF: {editor}"
                )

    # --------------------------------------------------------
    # 3. Incremental revision indicators
    # --------------------------------------------------------

    if structure["eof"] > 1:

        score += min(
            25,
            10 + (
                structure["eof"] - 2
            ) * 5,
        )

        reasons.append(
            "🟠 الملف يحتوي على أكثر من %%EOF."
        )

    if structure["prev"] > 0:

        score += min(
            25,
            structure["prev"] * 10,
        )

        reasons.append(
            "🟠 PDF يحتوي على /Prev revision chain."
        )

    # --------------------------------------------------------
    # 4. XMP / PDF mismatch
    # --------------------------------------------------------

    if len(
        date_differences
    ) >= 2:

        score += 15

        reasons.append(
            "🔴 PDF metadata وXMP غير متطابقين."
        )

    # --------------------------------------------------------
    # 5. MIME
    # --------------------------------------------------------

    if mime["magic"] != "application/pdf":

        score += 50

        reasons.append(
            "🔴 الملف لا يحمل PDF magic header."
        )

    if (
        mime["file"] not in (
            "unavailable",
            "",
            "application/pdf",
        )
    ):

        score += 20

        reasons.append(
            "🟠 MIME الحقيقي غير متوقع: "
            + mime["file"]
        )

    # --------------------------------------------------------
    # 6. JavaScript
    # --------------------------------------------------------

    if structure["javascript"]:

        score += 15

        reasons.append(
            "🟠 JavaScript موجود."
        )

    # --------------------------------------------------------
    # 7. Embedded
    # --------------------------------------------------------

    if structure["embedded"]:

        score += 5

        reasons.append(
            "🟠 Embedded file/object موجود."
        )

    # --------------------------------------------------------
    # 8. Annotations
    # --------------------------------------------------------

    if content["annotations"] > 0:

        score += min(
            10,
            content["annotations"] * 2,
        )

        reasons.append(
            f"🟠 Annotations: "
            f"{content['annotations']}"
        )

    # --------------------------------------------------------
    # 9. Forms
    # --------------------------------------------------------

    if content["forms"] > 0:

        score += 5

        reasons.append(
            f"🟠 Form fields: "
            f"{content['forms']}"
        )

    # --------------------------------------------------------
    # 10. Font anomalies
    # --------------------------------------------------------

    for item in content[
        "evidence"
    ]:

        score += 5

        reasons.append(
            "🟠 " + item
        )

    # --------------------------------------------------------
    # 11. Advanced
    # --------------------------------------------------------

    for item in advanced:

        score += 5

        reasons.append(
            "🟠 " + item
        )

    # --------------------------------------------------------
    # Limit
    # --------------------------------------------------------

    score = min(
        100,
        score,
    )

    reasons = unique(
        reasons
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if score >= 75:

        level = "🔴 HIGH RISK"
        meaning = (
            "مؤشرات تقنية قوية على التعديل أو "
            "إعادة المعالجة."
        )

    elif score >= 45:

        level = "🟠 MEDIUM RISK"
        meaning = (
            "توجد مؤشرات تستحق المراجعة."
        )

    elif score >= 20:

        level = "🟡 LOW RISK"
        meaning = (
            "توجد مؤشرات بسيطة، لكنها غير كافية."
        )

    else:

        level = "🟢 LOW INDICATIONS"
        meaning = (
            "لم تظهر مؤشرات تقنية قوية."
        )

    return {
        "score": score,
        "level": level,
        "meaning": meaning,
        "reasons": reasons,
    }


# ============================================================
# COMPLETE SCAN
# ============================================================

def forensic_scan(path):

    mime = mime_forensics(
        path
    )

    metadata = metadata_forensics(
        path
    )

    structure = structure_forensics(
        path
    )

    content = content_forensics(
        path
    )

    advanced = advanced_structure(
        path
    )

    result = calculate_score(
        metadata,
        structure,
        content,
        mime,
        advanced,
    )

    return {
        "mime": mime,
        "metadata": metadata,
        "structure": structure,
        "content": content,
        "advanced": advanced,
        "result": result,
    }


# ============================================================
# REPORT
# ============================================================

def make_report(
    filename,
    path,
    scan,
):

    mime = scan["mime"]
    metadata = scan["metadata"]
    structure = scan["structure"]
    content = scan["content"]
    result = scan["result"]

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

    size_mb = (
        path.stat().st_size
        / 1024
        / 1024
    )

    lines = [

        "🔎 LEX PDF FORENSIC PRO v3",

        "",
        f"📄 {filename}",
        f"📦 الحجم: {size_mb:.2f} MB",
        f"📑 الصفحات: {content['pages']}",

        "",
        result["level"],
        f"📊 Risk Score: "
        f"{result['score']}/100",

        f"📌 {result['meaning']}",

        "",
        "🌐 MIME FORENSICS",

        f"• Extension: "
        f"{mime['extension']}",

        f"• Real MIME: "
        f"{mime['file']}",

        f"• Magic: "
        f"{mime['magic']}",

        "",
        "📅 DATE FORENSICS",

        f"• CreationDate: "
        f"{metadata['creation_raw'] or 'غير موجود'}",

        f"• ModDate: "
        f"{metadata['modified_raw'] or 'غير موجود'}",

        f"• Create Date: "
        f"{metadata['create_raw'] or 'غير موجود'}",

        f"• Modify Date: "
        f"{metadata['modify_raw'] or 'غير موجود'}",

        "",
        "📝 METADATA",

        f"• Producer: {producer}",
        f"• Creator: {creator}",

        "",
        "🛠️ SOFTWARE",
    ]

    editors = unique(
        metadata["signatures"]
        + structure["editors"]
    )

    if editors:

        for editor in editors:

            lines.append(
                f"🔴 {editor}"
            )

    else:

        lines.append(
            "🟢 لم يتم العثور على بصمة معروفة"
        )

    lines += [

        "",
        "🔬 PDF STRUCTURE",

        f"• Objects: "
        f"{structure['objects']}",

        f"• Streams: "
        f"{structure['streams']}",

        f"• xref: "
        f"{structure['xref']}",

        f"• startxref: "
        f"{structure['startxref']}",

        f"• %%EOF: "
        f"{structure['eof']}",

        f"• /Prev: "
        f"{structure['prev']}",

        f"• Incremental indicators: "
        f"{'YES' if structure['prev'] > 0 or structure['eof'] > 1 else 'NO'}",

        f"• JavaScript: "
        f"{'YES' if structure['javascript'] else 'NO'}",

        f"• Embedded: "
        f"{'YES' if structure['embedded'] else 'NO'}",

        f"• Forms: "
        f"{'YES' if structure['forms'] else 'NO'}",

        f"• Signature indicator: "
        f"{'YES' if structure['signatures'] else 'NO'}",

        "",
        "📄 CONTENT",

        f"• Text pages: "
        f"{content['text_pages']}",

        f"• Image pages: "
        f"{content['image_pages']}",

        f"• Images: "
        f"{content['images']}",

        f"• Fonts: "
        f"{len(content['fonts'])}",

        f"• Annotations: "
        f"{content['annotations']}",

        f"• Form fields: "
        f"{content['forms']}",

        "",
        "⚠️ EVIDENCE",
    ]

    if result["reasons"]:

        for reason in result[
            "reasons"
        ][:25]:

            lines.append(
                "• " + reason
            )

    else:

        lines.append(
            "• لا توجد مؤشرات قوية."
        )

    lines += [

        "",
        "🔐 SHA-256",
        sha256(path),

        "",
        "⚠️ IMPORTANT",
        "هذه أداة PDF forensic تقنية.",
        "Risk Score لا يعني أن التزوير مثبت قانونيًا.",
        "أقوى تحقق يكون بمقارنة الملف مع النسخة الأصلية "
        "أو التحقق من توقيع رقمي موثوق.",

        "",
        "By LEX",
    ]

    return "\n".join(lines)


# ============================================================
# TELEGRAM
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
):

    await update.message.reply_text(
        "🤖 LEX PDF FORENSIC PRO v3\n\n"
        "أرسل أي PDF.\n\n"
        "🔬 Metadata + XMP\n"
        "📅 Creation / Modification dates\n"
        "🌐 Real MIME\n"
        "🛠️ Software fingerprints\n"
        "🔄 PDF revisions\n"
        "🔬 Objects / xref / /Prev\n"
        "🔤 Fonts\n"
        "🖼️ Images\n"
        "📝 Forms / annotations\n"
        "⚡ JavaScript / embedded files\n"
        "🔐 SHA-256\n\n"
        "سيعطيك Risk Score مع الأدلة."
    )


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

    size = document.file_size or 0

    if size > MAX_FILE_SIZE:

        await update.message.reply_text(
            f"❌ الملف أكبر من "
            f"{MAX_FILE_MB} MB."
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
            "🔍 استلمت PDF.\n"
            "جاري التحليل forensic..."
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
                "❌ هذا الملف لا يحتوي على PDF header صالح."
            )

            return

        scan = await asyncio.to_thread(
            forensic_scan,
            path,
        )

        report = make_report(
            filename,
            path,
            scan,
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
            "FORNSIC OK | %s | score=%s",
            filename,
            scan["result"]["score"],
        )

    except Exception as e:

        logger.exception(
            "FORNSIC FAILED"
        )

        try:

            await update.message.reply_text(
                "❌ فشل التحليل. "
                "تأكد أن الملف PDF صالح."
            )

        except Exception:
            pass

    finally:

        shutil.rmtree(
            workdir,
            ignore_errors=True,
        )


# ============================================================
# ERRORS
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
            "Another BOT instance is running."
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
        "🚀 LEX PDF FORENSIC PRO v3"
    )

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connect_timeout(20)
        .read_timeout(120)
        .write_timeout(120)
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
