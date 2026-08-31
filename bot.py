import os
import re
import io
import math
import hashlib
import logging
import tempfile
from collections import OrderedDict
from datetime import datetime, timezone

import fitz  # PyMuPDF

from telegram import Update
from telegram.constants import ChatAction
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

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)

logger = logging.getLogger("LEX-PDF-FORENSIC")


# ============================================================
# HELPERS
# ============================================================

def human_bytes(value: int) -> str:
    if value < 1024:
        return f"{value:,} B"

    if value < 1024 * 1024:
        return f"{value / 1024:.2f} KB"

    if value < 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024):.2f} MB"

    return f"{value / (1024 * 1024 * 1024):.2f} GB"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def clean_font_name(name: str) -> str:
    """
    Removes PDF subset prefix:

    ABCDEF+ArialMT -> ArialMT
    """

    if not name:
        return "Unknown"

    name = str(name).strip()

    # PDF subset font names normally look like:
    # ABCDEF+ArialMT
    name = re.sub(r"^[A-Z]{6}\+", "", name)

    return name


# ============================================================
# FONT ANALYSIS
# ============================================================

def get_xref_number(value):
    """
    Converts PDF object references such as:

    7 0 R

    into:

    7
    """

    if not value:
        return None

    if isinstance(value, int):
        return value

    m = re.search(r"(\d+)\s+\d+\s+R", str(value))

    if m:
        return int(m.group(1))

    return None


def get_dict_value(doc, xref: int, key: str):
    """
    Reads a PDF object dictionary value.
    """

    try:
        value = doc.xref_get_key(xref, key)

        if not value:
            return None

        if isinstance(value, tuple):
            return value[1]

        return value

    except Exception:
        return None


def get_embedded_font_size(doc, font_xref: int) -> int:
    """
    Finds FontDescriptor and embedded font streams.

    FontFile
    FontFile2
    FontFile3

    The raw stream size is used because this is the closest
    representation to the bytes physically stored in the PDF.
    """

    total = 0
    visited = set()

    try:
        descriptor_ref = get_dict_value(
            doc,
            font_xref,
            "FontDescriptor"
        )

        descriptor_xref = get_xref_number(descriptor_ref)

        if not descriptor_xref:
            return 0

        if descriptor_xref in visited:
            return 0

        visited.add(descriptor_xref)

        for key in ("FontFile", "FontFile2", "FontFile3"):

            stream_ref = get_dict_value(
                doc,
                descriptor_xref,
                key
            )

            stream_xref = get_xref_number(stream_ref)

            if not stream_xref:
                continue

            if stream_xref in visited:
                continue

            visited.add(stream_xref)

            # ------------------------------------------------
            # Preferred method:
            # actual raw bytes stored in the PDF
            # ------------------------------------------------

            try:
                raw_stream = doc.xref_stream_raw(stream_xref)

                if raw_stream is not None:
                    total += len(raw_stream)
                    continue

            except Exception:
                pass

            # ------------------------------------------------
            # Fallback: /Length
            # ------------------------------------------------

            try:
                length_value = get_dict_value(
                    doc,
                    stream_xref,
                    "Length"
                )

                if length_value:
                    match = re.search(
                        r"(\d+)",
                        str(length_value)
                    )

                    if match:
                        total += int(match.group(1))

            except Exception:
                pass

    except Exception:
        return total

    return total


def analyze_fonts(doc, file_size: int):
    """
    PDFCrowd-style font summary.

    Returns:

        font_count
        byte_size
        percentage
        fonts[]
    """

    fonts = OrderedDict()

    # --------------------------------------------------------
    # Collect fonts from every page
    # --------------------------------------------------------

    for page_number in range(len(doc)):

        try:
            page = doc[page_number]

            # full=True gives more detailed font information
            page_fonts = page.get_fonts(full=True)

        except Exception:
            continue

        for item in page_fonts:

            if not item:
                continue

            try:
                # PyMuPDF commonly returns:
                #
                # xref,
                # ext,
                # name,
                # type,
                # content,
                # ...
                #
                # Different versions may expose slightly
                # different tuple lengths, so we only depend
                # on the first values.

                xref = int(item[0])
                font_name = item[3] if len(item) > 3 else "Unknown"

                # Some PyMuPDF versions place the font name
                # at index 2.
                possible_name = item[2] if len(item) > 2 else ""

                if possible_name:
                    font_name = possible_name

                font_type = item[4] if len(item) > 4 else "Unknown"

            except Exception:
                continue

            if xref <= 0:
                continue

            if xref not in fonts:

                fonts[xref] = {
                    "xref": xref,
                    "name": clean_font_name(font_name),
                    "type": str(font_type),
                    "encoding": "Unknown",
                    "byte_size": 0,
                    "embedded": False,
                }

    # --------------------------------------------------------
    # Analyze every unique font
    # --------------------------------------------------------

    total_font_bytes = 0

    for xref, font in fonts.items():

        # Determine encoding
        try:
            encoding = get_dict_value(
                doc,
                xref,
                "Encoding"
            )

            if encoding:
                encoding = str(encoding)

                if "Identity-H" in encoding:
                    encoding = "Identity-H"

                elif "Identity-V" in encoding:
                    encoding = "Identity-V"

                elif "WinAnsiEncoding" in encoding:
                    encoding = "WinAnsi"

                elif "MacRomanEncoding" in encoding:
                    encoding = "MacRoman"

                else:
                    # Keep useful short representation
                    encoding = encoding[:60]

                font["encoding"] = encoding

        except Exception:
            pass

        # ----------------------------------------------------
        # Calculate embedded font stream size
        # ----------------------------------------------------

        size = get_embedded_font_size(
            doc,
            xref
        )

        font["byte_size"] = size
        font["embedded"] = size > 0

        total_font_bytes += size

    # --------------------------------------------------------
    # Percentage of complete PDF
    # --------------------------------------------------------

    if file_size > 0:
        percentage = (
            total_font_bytes / file_size
        ) * 100
    else:
        percentage = 0.0

    return {
        "font_count": len(fonts),
        "byte_size": total_font_bytes,
        "percentage": percentage,
        "fonts": list(fonts.values()),
    }


# ============================================================
# OBJECT ANALYSIS
# ============================================================

def analyze_objects(doc):
    result = {
        "xref_length": 0,
        "streams": 0,
        "images": 0,
        "pages": len(doc),
    }

    try:
        result["xref_length"] = doc.xref_length()

        streams = 0

        for xref in range(1, doc.xref_length()):

            try:
                obj = doc.xref_object(
                    xref,
                    compressed=False
                )

                if "stream" in obj:
                    streams += 1

            except Exception:
                pass

        result["streams"] = streams

    except Exception:
        pass

    # Images
    try:
        image_xrefs = set()

        for page in doc:
            for img in page.get_images(full=True):

                if img:
                    image_xrefs.add(img[0])

        result["images"] = len(image_xrefs)

    except Exception:
        pass

    return result


# ============================================================
# METADATA
# ============================================================

def analyze_metadata(doc):
    metadata = {}

    try:
        metadata = doc.metadata or {}
    except Exception:
        pass

    return {
        "title": metadata.get("title") or "",
        "author": metadata.get("author") or "",
        "subject": metadata.get("subject") or "",
        "creator": metadata.get("creator") or "",
        "producer": metadata.get("producer") or "",
        "creation_date": metadata.get("creationDate") or "",
        "mod_date": metadata.get("modDate") or "",
    }


# ============================================================
# FORENSIC REPORT
# ============================================================

def build_report(path: str):
    file_size = os.path.getsize(path)

    doc = fitz.open(path)

    try:
        fonts = analyze_fonts(
            doc,
            file_size
        )

        objects = analyze_objects(doc)

        metadata = analyze_metadata(doc)

        report = {
            "file_size": file_size,
            "pages": len(doc),
            "fonts": fonts,
            "objects": objects,
            "metadata": metadata,
            "pdf_version": getattr(
                doc,
                "pdf_version",
                "Unknown"
            ),
            "sha256": sha256_file(path),
        }

        return report

    finally:
        doc.close()


# ============================================================
# FORMAT FONT SECTION
# ============================================================

def format_fonts(report):
    fonts = report["fonts"]

    lines = []

    lines.append("Fonts")
    lines.append(
        f"Font count: {fonts['font_count']}"
    )

    lines.append(
        f"Byte size: {fonts['byte_size']:,} "
        f"({fonts['percentage']:.2f}% of the file)"
    )

    lines.append("")

    if fonts["fonts"]:

        lines.append(
            "object name        type              encoding"
        )

        for font in fonts["fonts"]:

            xref = font["xref"]

            name = font["name"][:24]

            font_type = font["type"][:18]

            encoding = font["encoding"][:18]

            lines.append(
                f"{xref} 0               "
                f"{name:<18} "
                f"{font_type:<16} "
                f"{encoding}"
            )

    else:

        lines.append(
            "No font objects detected."
        )

    return "\n".join(lines)


# ============================================================
# FORMAT FULL REPORT
# ============================================================

def format_report(report):

    fonts = report["fonts"]
    objects = report["objects"]
    metadata = report["metadata"]

    lines = []

    lines.append("🔎 LEX PDF FORENSIC PRO")
    lines.append("")
    lines.append("📄 PDF Analysis")
    lines.append("────────────────────────")
    lines.append(
        f"Pages: {report['pages']}"
    )

    lines.append(
        f"File size: {report['file_size']:,} bytes"
    )

    lines.append(
        f"PDF version: {report['pdf_version']}"
    )

    lines.append("")

    # ========================================================
    # FONTS — IMPORTANT
    # ========================================================

    lines.append(
        format_fonts(report)
    )

    lines.append("")

    # ========================================================
    # OBJECTS
    # ========================================================

    lines.append("Objects")
    lines.append("────────────────────────")

    lines.append(
        f"XRef objects: {objects['xref_length']}"
    )

    lines.append(
        f"Streams: {objects['streams']}"
    )

    lines.append(
        f"Images: {objects['images']}"
    )

    lines.append("")

    # ========================================================
    # METADATA
    # ========================================================

    lines.append("Metadata")
    lines.append("────────────────────────")

    if metadata["title"]:
        lines.append(
            f"Title: {metadata['title']}"
        )

    if metadata["author"]:
        lines.append(
            f"Author: {metadata['author']}"
        )

    if metadata["creator"]:
        lines.append(
            f"Creator: {metadata['creator']}"
        )

    if metadata["producer"]:
        lines.append(
            f"Producer: {metadata['producer']}"
        )

    if metadata["creation_date"]:
        lines.append(
            f"Creation: {metadata['creation_date']}"
        )

    if metadata["mod_date"]:
        lines.append(
            f"Modified: {metadata['mod_date']}"
        )

    lines.append("")

    # ========================================================
    # HASH
    # ========================================================

    lines.append("SHA-256")
    lines.append("────────────────────────")
    lines.append(report["sha256"])

    return "\n".join(lines)


# ============================================================
# /START
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):

    await update.message.reply_text(
        "🔎 LEX PDF FORENSIC PRO\n\n"
        "أرسل ملف PDF وسأقوم بتحليله.\n\n"
        "يتم فحص:\n"
        "• Fonts\n"
        "• Font Byte Size\n"
        "• % of file\n"
        "• Embedded fonts\n"
        "• Objects\n"
        "• Streams\n"
        "• Images\n"
        "• Metadata\n"
        "• SHA-256"
    )


# ============================================================
# PDF HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    if not update.message:
        return

    document = update.message.document

    if not document:
        return

    filename = document.file_name or "document.pdf"

    if not filename.lower().endswith(".pdf"):

        await update.message.reply_text(
            "❌ الملف لازم يكون PDF."
        )

        return

    if document.file_size and document.file_size > MAX_FILE_SIZE:

        await update.message.reply_text(
            "❌ حجم الملف أكبر من الحد المسموح."
        )

        return

    await update.message.chat.send_action(
        action=ChatAction.UPLOAD_DOCUMENT
    )

    status = await update.message.reply_text(
        "🔎 جاري فحص PDF...\n"
        "⏳ تحليل Fonts و Objects..."
    )

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False
        ) as tmp:

            temp_path = tmp.name

        telegram_file = await context.bot.get_file(
            document.file_id
        )

        await telegram_file.download_to_drive(
            temp_path
        )

        # Verify PDF
        try:
            test_doc = fitz.open(temp_path)

            if test_doc.page_count == 0:
                test_doc.close()

                raise ValueError(
                    "PDF contains no pages"
                )

            test_doc.close()

        except Exception as e:

            await status.edit_text(
                f"❌ الملف ليس PDF صالحًا.\n\n{e}"
            )

            return

        # ----------------------------------------------------
        # FORENSIC ANALYSIS
        # ----------------------------------------------------

        report = build_report(
            temp_path
        )

        text = format_report(
            report
        )

        # Telegram message limit protection
        if len(text) > 3900:

            text = text[:3850] + "\n\n…"

        await status.edit_text(
            text
        )

    except Exception as e:

        logger.exception(
            "PDF analysis failed"
        )

        await status.edit_text(
            "❌ حدث خطأ أثناء تحليل PDF.\n\n"
            f"{type(e).__name__}: {e}"
        )

    finally:

        if temp_path:

            try:
                os.remove(temp_path)
            except Exception:
                pass


# ============================================================
# ERROR HANDLER
# ============================================================

async def error_handler(
    update: object,
    context: ContextTypes.DEFAULT_TYPE
):

    logger.error(
        "Telegram error: %s",
        context.error
    )


# ============================================================
# MAIN
# ============================================================

def main():

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    application.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    application.add_handler(
        CommandHandler(
            "hello",
            start
        )
    )

    application.add_handler(
        MessageHandler(
            filters.Document.ALL,
            handle_pdf
        )
    )

    application.add_error_handler(
        error_handler
    )

    logger.info(
        "LEX PDF FORENSIC PRO started"
    )

    application.run_polling(
        drop_pending_updates=True
    )


if __name__ == "__main__":
    main()
