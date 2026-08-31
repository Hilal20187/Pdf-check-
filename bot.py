import os
import re
import logging
import tempfile
import hashlib
import zlib

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
    raise RuntimeError("BOT_TOKEN environment variable is missing")


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | LEX | %(levelname)s | %(message)s"
)

logger = logging.getLogger("LEX")


# ============================================================
# LIMITS
# ============================================================

MAX_FILE_SIZE = 30 * 1024 * 1024


# ============================================================
# PDF RAW INSPECTOR
# ============================================================

def inspect_raw_pdf(path):

    result = {
        "size": 0,
        "sha256": "",
        "header": False,
        "eof": False,
        "objects": 0,
        "streams": 0,
        "endstreams": 0,
        "xref": 0,
        "startxref": 0,
        "trailer": 0,
        "prev": 0,
        "objstm": 0,
        "images": 0,
        "fonts": 0,
        "javascript": 0,
        "openaction": 0,
        "embedded_files": 0,
        "annots": 0,
        "acroform": 0,
        "metadata": 0,
        "errors": [],
    }

    try:

        with open(path, "rb") as f:
            data = f.read()

        result["size"] = len(data)

        result["sha256"] = hashlib.sha256(data).hexdigest()

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        result["header"] = data.startswith(b"%PDF-")

        # ----------------------------------------------------
        # EOF
        # ----------------------------------------------------

        result["eof"] = b"%%EOF" in data[-8192:]

        # ----------------------------------------------------
        # OBJECTS
        # ----------------------------------------------------

        result["objects"] = len(
            re.findall(
                rb"(?m)^\s*\d+\s+\d+\s+obj\b",
                data
            )
        )

        # ----------------------------------------------------
        # STREAMS
        # ----------------------------------------------------

        result["streams"] = len(
            re.findall(
                rb"(?m)^\s*stream(?:\r\n|\n|\r)",
                data
            )
        )

        result["endstreams"] = len(
            re.findall(
                rb"(?m)^\s*endstream\b",
                data
            )
        )

        # ----------------------------------------------------
        # XREF / TRAILER
        # ----------------------------------------------------

        result["xref"] = len(
            re.findall(
                rb"(?m)^\s*xref\s*$",
                data
            )
        )

        result["startxref"] = len(
            re.findall(
                rb"startxref",
                data
            )
        )

        result["trailer"] = len(
            re.findall(
                rb"(?m)^\s*trailer\b",
                data
            )
        )

        # ----------------------------------------------------
        # INCREMENTAL UPDATE
        # ----------------------------------------------------

        result["prev"] = len(
            re.findall(
                rb"/Prev\s+\d+",
                data
            )
        )

        # ----------------------------------------------------
        # OBJECT STREAMS
        # ----------------------------------------------------

        result["objstm"] = len(
            re.findall(
                rb"/Type\s*/ObjStm",
                data
            )
        )

        # ----------------------------------------------------
        # IMAGES
        # ----------------------------------------------------

        result["images"] = len(
            re.findall(
                rb"/Subtype\s*/Image",
                data
            )
        )

        # ----------------------------------------------------
        # FONTS
        # ----------------------------------------------------

        result["fonts"] = len(
            re.findall(
                rb"/Type\s*/Font\b",
                data
            )
        )

        # ----------------------------------------------------
        # JAVASCRIPT
        # ----------------------------------------------------

        result["javascript"] = (
            len(re.findall(rb"/JavaScript\b", data)) +
            len(re.findall(rb"/JS\b", data))
        )

        # ----------------------------------------------------
        # OPEN ACTION
        # ----------------------------------------------------

        result["openaction"] = len(
            re.findall(
                rb"/OpenAction\b",
                data
            )
        )

        # ----------------------------------------------------
        # EMBEDDED FILES
        # ----------------------------------------------------

        result["embedded_files"] = len(
            re.findall(
                rb"/EmbeddedFile\b",
                data
            )
        )

        # ----------------------------------------------------
        # ANNOTATIONS
        # ----------------------------------------------------

        result["annots"] = len(
            re.findall(
                rb"/Annot\b",
                data
            )
        )

        # ----------------------------------------------------
        # ACROFORM
        # ----------------------------------------------------

        result["acroform"] = len(
            re.findall(
                rb"/AcroForm\b",
                data
            )
        )

        # ----------------------------------------------------
        # METADATA
        # ----------------------------------------------------

        result["metadata"] = (
            len(re.findall(rb"/Metadata\b", data))
            +
            len(re.findall(rb"/Info\b", data))
        )

    except Exception as e:

        result["errors"].append(str(e))

    return result


# ============================================================
# PDF DOCUMENT INSPECTION
# ============================================================

def inspect_document(path):

    result = {
        "pages": 0,
        "metadata": {},
        "fonts": 0,
        "images": 0,
        "text_pages": 0,
        "empty_pages": 0,
        "page_sizes": [],
        "links": 0,
        "annotations": 0,
        "forms": 0,
        "encrypted": False,
        "open_error": False,
    }

    doc = None

    try:

        doc = fitz.open(path)

        result["pages"] = doc.page_count

        result["encrypted"] = doc.is_encrypted

        result["metadata"] = doc.metadata or {}

        font_set = set()
        image_count = 0

        for page in doc:

            # ------------------------------------------------
            # PAGE SIZE
            # ------------------------------------------------

            rect = page.rect

            result["page_sizes"].append(
                (
                    round(rect.width, 2),
                    round(rect.height, 2)
                )
            )

            # ------------------------------------------------
            # TEXT
            # ------------------------------------------------

            try:

                text = page.get_text("text")

                if text and text.strip():
                    result["text_pages"] += 1
                else:
                    result["empty_pages"] += 1

            except Exception:
                pass

            # ------------------------------------------------
            # IMAGES
            # ------------------------------------------------

            try:

                images = page.get_images(full=True)

                image_count += len(images)

            except Exception:
                pass

            # ------------------------------------------------
            # FONTS
            # ------------------------------------------------

            try:

                fonts = page.get_fonts(full=True)

                for font in fonts:
                    if font:
                        font_set.add(
                            tuple(font[:4])
                        )

            except Exception:
                pass

            # ------------------------------------------------
            # LINKS
            # ------------------------------------------------

            try:
                result["links"] += len(page.get_links())
            except Exception:
                pass

            # ------------------------------------------------
            # ANNOTATIONS
            # ------------------------------------------------

            try:

                annotations = page.annots()

                if annotations:

                    for _ in annotations:
                        result["annotations"] += 1

            except Exception:
                pass

        result["images"] = image_count
        result["fonts"] = len(font_set)

        # ----------------------------------------------------
        # FORMS
        # ----------------------------------------------------

        try:

            for page in doc:

                widgets = page.widgets()

                if widgets:

                    for _ in widgets:
                        result["forms"] += 1

        except Exception:
            pass

    except Exception:

        result["open_error"] = True

    finally:

        if doc:

            try:
                doc.close()
            except Exception:
                pass

    return result


# ============================================================
# STRUCTURAL CONSISTENCY
# ============================================================

def structural_check(raw, doc):

    suspicious = 0

    # --------------------------------------------------------
    # Invalid PDF header
    # --------------------------------------------------------

    if not raw["header"]:
        suspicious += 100

    # --------------------------------------------------------
    # Missing EOF
    # --------------------------------------------------------

    if not raw["eof"]:
        suspicious += 40

    # --------------------------------------------------------
    # PDF cannot be opened
    # --------------------------------------------------------

    if doc["open_error"]:
        suspicious += 100

    # --------------------------------------------------------
    # No pages
    # --------------------------------------------------------

    if doc["pages"] <= 0:
        suspicious += 50

    # --------------------------------------------------------
    # Broken stream balance
    # --------------------------------------------------------

    stream_difference = abs(
        raw["streams"] -
        raw["endstreams"]
    )

    if stream_difference > 0:
        suspicious += 35

    # --------------------------------------------------------
    # Object count
    # --------------------------------------------------------

    if raw["objects"] == 0:
        suspicious += 50

    # --------------------------------------------------------
    # startxref
    # --------------------------------------------------------

    if raw["startxref"] == 0:
        suspicious += 30

    # --------------------------------------------------------
    # Page structure
    # --------------------------------------------------------

    if doc["pages"] > 1:

        sizes = set(
            doc["page_sizes"]
        )

        # Different page sizes are NOT automatically suspicious.
        # Only a small signal.
        if len(sizes) > 4:
            suspicious += 2

    # --------------------------------------------------------
    # Incremental revisions
    # --------------------------------------------------------

    # IMPORTANT:
    # /Prev is NOT automatically forgery.
    #
    # It is a valid PDF feature.
    #
    # Therefore only a very small signal is used.
    # --------------------------------------------------------

    if raw["prev"] >= 3:
        suspicious += 4

    # --------------------------------------------------------
    # JavaScript
    # --------------------------------------------------------

    if raw["javascript"] > 0:
        suspicious += 15

    # --------------------------------------------------------
    # OpenAction
    # --------------------------------------------------------

    if raw["openaction"] > 0:
        suspicious += 8

    # --------------------------------------------------------
    # Embedded files
    # --------------------------------------------------------

    if raw["embedded_files"] > 0:
        suspicious += 5

    return min(
        suspicious,
        100
    )


# ============================================================
# FORENSIC DECISION
# ============================================================

def analyze_pdf(path):

    raw = inspect_raw_pdf(path)

    doc = inspect_document(path)

    structural_score = structural_check(
        raw,
        doc
    )

    # ========================================================
    # IMPORTANT
    # ========================================================
    #
    # Metadata such as ModDate is NOT treated as proof.
    #
    # BaridiMob PDFs can legitimately contain:
    # - streams
    # - images
    # - fonts
    # - metadata
    # - creation/modification information
    #
    # Therefore we do NOT mark them suspicious simply because
    # these fields exist.
    #
    # ========================================================

    metadata = doc.get(
        "metadata",
        {}
    )

    producer = str(
        metadata.get(
            "producer",
            ""
        )
    ).lower()

    creator = str(
        metadata.get(
            "creator",
            ""
        )
    ).lower()

    # --------------------------------------------------------
    # Strong corruption indicators
    # --------------------------------------------------------

    if raw["errors"]:
        structural_score += 30

    # --------------------------------------------------------
    # Contradictory raw structure
    # --------------------------------------------------------

    if (
        raw["xref"] == 0
        and raw["objstm"] == 0
        and raw["startxref"] == 0
    ):
        structural_score += 20

    # --------------------------------------------------------
    # Excessive annotation/form manipulation
    # --------------------------------------------------------

    if doc["annotations"] > 30:
        structural_score += 5

    if doc["forms"] > 20:
        structural_score += 5

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    structural_score = min(
        structural_score,
        100
    )

    if structural_score >= 25:
        verdict = "مشبوه"
    else:
        verdict = "صحيح"

    return verdict


# ============================================================
# TELEGRAM HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.effective_message

    if not message or not message.document:
        return

    document = message.document

    filename = (
        document.file_name
        or "document.pdf"
    )

    # --------------------------------------------------------
    # PDF ONLY
    # --------------------------------------------------------

    if not filename.lower().endswith(".pdf"):
        return

    # --------------------------------------------------------
    # SIZE LIMIT
    # --------------------------------------------------------

    if (
        document.file_size
        and document.file_size > MAX_FILE_SIZE
    ):
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
        # ANALYZE
        # ----------------------------------------------------

        verdict = analyze_pdf(
            temp_path
        )

        # ----------------------------------------------------
        # ONLY USER OUTPUT
        # ----------------------------------------------------

        await message.reply_text(
            f"{verdict}\n\nBy LEX"
        )

    except Exception as e:

        logger.exception(
            "LEX PDF error: %s",
            e
        )

        # Fail closed:
        # if forensic engine cannot safely inspect it,
        # don't call it authentic.
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
# MAIN
# ============================================================

def main():

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    app.add_handler(
        MessageHandler(
            filters.Document.PDF,
            handle_pdf
        )
    )

    logger.info(
        "LEX PDF FORENSIC BOT STARTED"
    )

    app.run_polling(
        drop_pending_updates=True
    )


if __name__ == "__main__":
    main()

"requirements.txt":

python-telegram-bot==22.5
PyMuPDF==1.26.4

هذا الإصدار يتعمد عدم اعتبار "ModDate" أو وجود الصور أو الـfonts أو الـstreams تزويرًا بحد ذاته، لأن PDFCrowd نفسه يعرض هذه العناصر كجزء من بنية الـPDF التي يتم فحصها، وليس كحكم تلقائي بأن الملف مزور.

والبوت للمستخدم النهائي سيُظهر فقط:

صحيح

By LEX

أو:

مشبوه

By LEX

ولا يرسل "Byte size" ولا metadata ولا score ولا أسباب الفحص. 
