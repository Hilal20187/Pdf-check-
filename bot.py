import os
import re
import hashlib
import tempfile
import subprocess
import mimetypes
from pathlib import Path

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

BOT_TOKEN = os.getenv("BOT_TOKEN")

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def read_metadata(path):
    result = {}

    try:
        from pypdf import PdfReader

        reader = PdfReader(path)

        if reader.metadata:
            for key, value in reader.metadata.items():
                if value is not None:
                    result[str(key)] = str(value)

    except Exception:
        pass

    return result


def inspect_pdf_structure(path):
    findings = []

    with open(path, "rb") as f:
        data = f.read()

    # PDF header
    if not data.startswith(b"%PDF-"):
        findings.append("Invalid PDF header")

    # Incremental update indicators
    startxref_count = len(re.findall(rb"\bstartxref\b", data))
    prev_count = len(re.findall(rb"/Prev\b", data))

    if startxref_count > 1:
        findings.append(
            f"Multiple startxref sections detected ({startxref_count})"
        )

    if prev_count > 0:
        findings.append(
            f"Previous revision reference detected (/Prev: {prev_count})"
        )

    # EOF markers
    eof_count = len(re.findall(rb"%%EOF", data))

    if eof_count > 1:
        findings.append(
            f"Multiple EOF markers detected ({eof_count})"
        )

    # Metadata fields
    creation_dates = re.findall(
        rb"/CreationDate\s*\((.*?)\)", data, re.DOTALL
    )

    mod_dates = re.findall(
        rb"/ModDate\s*\((.*?)\)", data, re.DOTALL
    )

    if creation_dates:
        result_creation = creation_dates[-1].decode(
            "latin-1", errors="ignore"
        )
    else:
        result_creation = None

    if mod_dates:
        result_mod = mod_dates[-1].decode(
            "latin-1", errors="ignore"
        )
    else:
        result_mod = None

    # Detect metadata revisions / duplicated metadata
    if len(creation_dates) > 1:
        findings.append(
            f"Multiple CreationDate entries detected ({len(creation_dates)})"
        )

    if len(mod_dates) > 1:
        findings.append(
            f"Multiple ModDate entries detected ({len(mod_dates)})"
        )

    # Producer / Creator
    producers = re.findall(
        rb"/Producer\s*\((.*?)\)", data, re.DOTALL
    )

    creators = re.findall(
        rb"/Creator\s*\((.*?)\)", data, re.DOTALL
    )

    producer = (
        producers[-1].decode("latin-1", errors="ignore")
        if producers else None
    )

    creator = (
        creators[-1].decode("latin-1", errors="ignore")
        if creators else None
    )

    # Digital signature
    has_signature = (
        b"/Sig" in data or
        b"/ByteRange" in data or
        b"/FT /Sig" in data
    )

    if has_signature:
        findings.append("Digital signature structures detected")

    # XMP
    has_xmp = (
        b"<x:xmpmeta" in data or
        b"<rdf:RDF" in data
    )

    return {
        "findings": findings,
        "creation": result_creation,
        "modification": result_mod,
        "producer": producer,
        "creator": creator,
        "has_signature": has_signature,
        "has_xmp": has_xmp,
        "startxref_count": startxref_count,
        "prev_count": prev_count,
        "eof_count": eof_count,
    }


def analyze_pdf(path):
    findings = []

    metadata = read_metadata(path)
    structure = inspect_pdf_structure(path)

    findings.extend(structure["findings"])

    # Stronger indicators
    strong_indicators = 0

    if structure["prev_count"] > 0:
        strong_indicators += 2

    if structure["startxref_count"] > 1:
        strong_indicators += 2

    if structure["eof_count"] > 1:
        strong_indicators += 1

    if len(re.findall(
        rb"/ModDate\s*\(",
        open(path, "rb").read()
    )) > 1:
        strong_indicators += 1

    # Check metadata inconsistencies
    creation = structure["creation"]
    modification = structure["modification"]

    if creation and modification and creation != modification:
        findings.append(
            "CreationDate and ModDate are different"
        )

    # Determine result
    if strong_indicators >= 3:
        result = "🔴 تم اكتشاف شبهة قوية في تعديل الملف"

    elif strong_indicators >= 1:
        result = "🟠 تم اكتشاف شبهة في تعديل الملف"

    else:
        result = "🟢 لم يتم اكتشاف أي تعديل مشبوه"

    if not findings:
        suspicion = "لا توجد شبهة في التعديل"
    else:
        suspicion = "\n".join(
            f"• {x}" for x in findings[:5]
        )

    return {
        "metadata": metadata,
        "structure": structure,
        "findings": findings,
        "result": result,
        "suspicion": suspicion,
    }


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔎 LEX PDF FORENSIC PRO\n\n"
        "Send me a PDF file for forensic analysis."
    )


async def handle_pdf(update: Update, context: ContextTypes.DEFAULT_TYPE):

    document = update.message.document

    if not document:
        return

    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            "❌ File is too large. Maximum size is 50 MB."
        )
        return

    filename = document.file_name or "document.pdf"

    if not filename.lower().endswith(".pdf"):
        await update.message.reply_text(
            "❌ Please send a PDF file."
        )
        return

    processing = await update.message.reply_text(
        "🔎 Analyzing PDF..."
    )

    temp_path = None

    try:
        telegram_file = await document.get_file()

        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False
        ) as tmp:
            temp_path = tmp.name

        await telegram_file.download_to_drive(temp_path)

        # MIME detection
        mime_type, _ = mimetypes.guess_type(filename)

        # Real PDF signature check
        with open(temp_path, "rb") as f:
            header = f.read(5)

        if header != b"%PDF-":
            await processing.edit_text(
                "❌ Invalid PDF file."
            )
            return

        file_hash = sha256_file(temp_path)

        analysis = analyze_pdf(temp_path)

        structure = analysis["structure"]

        text = (
            "🔎 LEX PDF FORENSIC PRO\n\n"

            f"📄 File: {filename}\n"
            f"📦 Size: {document.file_size or 0:,} bytes\n"
            f"🧬 MIME Type: {mime_type or 'application/pdf'}\n\n"

            f"🔐 SHA-256:\n"
            f"{file_hash}\n\n"

            f"📊 النتيجة:\n"
            f"{analysis['result']}\n\n"

            f"⚠️ شبهة:\n"
            f"{analysis['suspicion']}\n\n"

            "━━━━━━━━━━━━━━━━━━\n"
            "By LEX"
        )

        await processing.edit_text(text)

    except Exception as e:

        await processing.edit_text(
            "❌ Analysis failed.\n\n"
            f"Error: {str(e)[:500]}"
        )

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    print(
        "ERROR:",
        context.error
    )


def main():

    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN environment variable is missing."
        )

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    app.add_handler(
        CommandHandler("start", start)
    )

    app.add_handler(
        MessageHandler(
            filters.Document.PDF,
            handle_pdf
        )
    )

    app.add_error_handler(error_handler)

    print("LEX PDF FORENSIC PRO started.")

    app.run_polling(
        drop_pending_updates=True
    )


if __name__ == "__main__":
    main()
