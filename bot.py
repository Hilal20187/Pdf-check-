import os
import re
import hashlib
import tempfile
import mimetypes

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from pypdf import PdfReader


# ============================================================
# CONFIG
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# PDF METADATA
# ============================================================

def get_pdf_metadata(file_path):
    metadata = {}

    try:
        reader = PdfReader(file_path)

        if reader.metadata:
            for key, value in reader.metadata.items():

                if value is not None:
                    metadata[str(key)] = str(value)

    except Exception:
        pass

    return metadata


# ============================================================
# RAW PDF ANALYSIS
# ============================================================

def analyze_pdf_structure(file_path):

    findings = []

    with open(file_path, "rb") as f:
        data = f.read()

    # --------------------------------------------------------
    # PDF HEADER
    # --------------------------------------------------------

    if not data.startswith(b"%PDF-"):
        findings.append(
            "Invalid PDF header"
        )

    # --------------------------------------------------------
    # STARTXREF
    # --------------------------------------------------------

    startxref_matches = re.findall(
        rb"\bstartxref\b",
        data
    )

    startxref_count = len(startxref_matches)

    if startxref_count > 1:

        findings.append(
            f"Multiple startxref sections detected ({startxref_count})"
        )

    # --------------------------------------------------------
    # /PREV
    # --------------------------------------------------------

    prev_matches = re.findall(
        rb"/Prev\b",
        data
    )

    prev_count = len(prev_matches)

    if prev_count > 0:

        findings.append(
            f"Previous revision reference detected (/Prev: {prev_count})"
        )

    # --------------------------------------------------------
    # EOF
    # --------------------------------------------------------

    eof_matches = re.findall(
        rb"%%EOF",
        data
    )

    eof_count = len(eof_matches)

    if eof_count > 1:

        findings.append(
            f"Multiple EOF markers detected ({eof_count})"
        )

    # --------------------------------------------------------
    # CREATION DATE
    # --------------------------------------------------------

    creation_dates = re.findall(
        rb"/CreationDate\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    # --------------------------------------------------------
    # MODIFICATION DATE
    # --------------------------------------------------------

    modification_dates = re.findall(
        rb"/ModDate\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    creation_date = None
    modification_date = None

    if creation_dates:

        creation_date = creation_dates[-1].decode(
            "latin-1",
            errors="ignore"
        )

    if modification_dates:

        modification_date = modification_dates[-1].decode(
            "latin-1",
            errors="ignore"
        )

    # --------------------------------------------------------
    # DUPLICATE DATE ENTRIES
    # --------------------------------------------------------

    if len(creation_dates) > 1:

        findings.append(
            f"Multiple CreationDate entries detected ({len(creation_dates)})"
        )

    if len(modification_dates) > 1:

        findings.append(
            f"Multiple ModDate entries detected ({len(modification_dates)})"
        )

    # --------------------------------------------------------
    # CREATION / MODIFICATION DIFFERENCE
    # --------------------------------------------------------

    if (
        creation_date
        and modification_date
        and creation_date != modification_date
    ):

        findings.append(
            "CreationDate and ModDate are different"
        )

    # --------------------------------------------------------
    # PRODUCER
    # --------------------------------------------------------

    producer_matches = re.findall(
        rb"/Producer\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    producer = None

    if producer_matches:

        producer = producer_matches[-1].decode(
            "latin-1",
            errors="ignore"
        )

    # --------------------------------------------------------
    # CREATOR
    # --------------------------------------------------------

    creator_matches = re.findall(
        rb"/Creator\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    creator = None

    if creator_matches:

        creator = creator_matches[-1].decode(
            "latin-1",
            errors="ignore"
        )

    # --------------------------------------------------------
    # XMP
    # --------------------------------------------------------

    has_xmp = (
        b"<x:xmpmeta" in data
        or
        b"<rdf:RDF" in data
    )

    # --------------------------------------------------------
    # DIGITAL SIGNATURE
    # --------------------------------------------------------

    has_signature = (
        b"/ByteRange" in data
        or
        b"/FT /Sig" in data
        or
        b"/Sig" in data
    )

    # --------------------------------------------------------
    # OBJECT COUNT
    # --------------------------------------------------------

    object_matches = re.findall(
        rb"\n\d+\s+\d+\s+obj\b",
        data
    )

    object_count = len(object_matches)

    # --------------------------------------------------------
    # RETURN
    # --------------------------------------------------------

    return {
        "findings": findings,
        "creation_date": creation_date,
        "modification_date": modification_date,
        "producer": producer,
        "creator": creator,
        "has_xmp": has_xmp,
        "has_signature": has_signature,
        "startxref_count": startxref_count,
        "prev_count": prev_count,
        "eof_count": eof_count,
        "object_count": object_count,
    }


# ============================================================
# FORENSIC ANALYSIS
# ============================================================

def forensic_analysis(file_path):

    structure = analyze_pdf_structure(
        file_path
    )

    findings = list(
        structure["findings"]
    )

    metadata = get_pdf_metadata(
        file_path
    )

    # --------------------------------------------------------
    # CHECK METADATA CONSISTENCY
    # --------------------------------------------------------

    metadata_creation = metadata.get(
        "/CreationDate"
    )

    metadata_modification = metadata.get(
        "/ModDate"
    )

    if (
        metadata_creation
        and metadata_modification
        and metadata_creation != metadata_modification
    ):

        if (
            "CreationDate and ModDate are different"
            not in findings
        ):

            findings.append(
                "CreationDate and ModDate are different"
            )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    # IMPORTANT:
    # ANY FINDING = RED
    # NO FINDINGS = GREEN

    if findings:

        result = (
            "🔴 تم اكتشاف شبهة في تعديل الملف"
        )

        suspicion = "\n".join(
            f"• {finding}"
            for finding in findings[:8]
        )

    else:

        result = (
            "🟢 لم يتم اكتشاف أي تعديل مشبوه"
        )

        suspicion = (
            "لا توجد شبهة في التعديل"
        )

    return {
        "result": result,
        "suspicion": suspicion,
        "findings": findings,
        "metadata": metadata,
        "structure": structure,
    }


# ============================================================
# START COMMAND
# ============================================================

async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    await update.message.reply_text(
        "🔎 LEX PDF FORENSIC PRO\n\n"
        "Send a PDF file for forensic analysis."
    )


# ============================================================
# PDF HANDLER
# ============================================================

async def handle_pdf(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    document = update.message.document

    if not document:
        return

    # --------------------------------------------------------
    # FILE SIZE
    # --------------------------------------------------------

    if (
        document.file_size
        and document.file_size > MAX_FILE_SIZE
    ):

        await update.message.reply_text(
            "❌ File is too large.\n"
            "Maximum size: 50 MB."
        )

        return

    # --------------------------------------------------------
    # FILE NAME
    # --------------------------------------------------------

    filename = (
        document.file_name
        or
        "document.pdf"
    )

    if not filename.lower().endswith(".pdf"):

        await update.message.reply_text(
            "❌ Please send a PDF file."
        )

        return

    processing_message = await update.message.reply_text(
        "🔎 Analyzing PDF..."
    )

    temp_path = None

    try:

        # ----------------------------------------------------
        # DOWNLOAD
        # ----------------------------------------------------

        telegram_file = await document.get_file()

        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False
        ) as tmp:

            temp_path = tmp.name

        await telegram_file.download_to_drive(
            temp_path
        )

        # ----------------------------------------------------
        # REAL PDF CHECK
        # ----------------------------------------------------

        with open(
            temp_path,
            "rb"
        ) as f:

            header = f.read(5)

        if header != b"%PDF-":

            await processing_message.edit_text(
                "❌ Invalid PDF file."
            )

            return

        # ----------------------------------------------------
        # MIME TYPE
        # ----------------------------------------------------

        mime_type, _ = mimetypes.guess_type(
            filename
        )

        if not mime_type:

            mime_type = "application/pdf"

        # ----------------------------------------------------
        # SHA-256
        # ----------------------------------------------------

        file_hash = calculate_sha256(
            temp_path
        )

        # ----------------------------------------------------
        # FORENSIC
        # ----------------------------------------------------

        analysis = forensic_analysis(
            temp_path
        )

        # ----------------------------------------------------
        # RESULT MESSAGE
        # ----------------------------------------------------

        file_size = (
            document.file_size
            or
            os.path.getsize(temp_path)
        )

        message = (
            "🔎 LEX PDF FORENSIC PRO\n\n"

            f"📄 File: {filename}\n"
            f"📦 Size: {file_size:,} bytes\n"
            f"🧬 MIME Type: {mime_type}\n\n"

            "🔐 SHA-256:\n"
            f"{file_hash}\n\n"

            "📊 النتيجة:\n"
            f"{analysis['result']}\n\n"

            "⚠️ شبهة:\n"
            f"{analysis['suspicion']}\n\n"

            "━━━━━━━━━━━━━━━━━━\n"
            "By LEX"
        )

        await processing_message.edit_text(
            message
        )

    except Exception as error:

        print(
            "PDF ANALYSIS ERROR:",
            repr(error)
        )

        try:

            await processing_message.edit_text(
                "❌ Analysis failed.\n\n"
                f"Error: {str(error)[:500]}"
            )

        except Exception:
            pass

    finally:

        # ----------------------------------------------------
        # DELETE TEMP FILE
        # ----------------------------------------------------

        if (
            temp_path
            and
            os.path.exists(temp_path)
        ):

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

    print(
        "BOT ERROR:",
        repr(context.error)
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not BOT_TOKEN:

        raise RuntimeError(
            "BOT_TOKEN environment variable is missing."
        )

    application = (
        Application
        .builder()
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
        MessageHandler(
            filters.Document.PDF,
            handle_pdf
        )
    )

    application.add_error_handler(
        error_handler
    )

    print(
        "LEX PDF FORENSIC PRO started."
    )

    application.run_polling(
        drop_pending_updates=True
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()
