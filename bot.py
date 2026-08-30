import os
import re
import hashlib
import tempfile
import mimetypes
from datetime import datetime, timezone

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

MAX_FILE_SIZE = 50 * 1024 * 1024

# Difference considered suspicious when PDF metadata
# is BEFORE the transaction date.
#
# 5 minutes tolerance is used for clock differences.
TIME_TOLERANCE_SECONDS = 300


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
# RAW PDF DATA
# ============================================================

def read_pdf_bytes(file_path):

    with open(file_path, "rb") as f:
        return f.read()


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
# PDF DATE PARSER
# ============================================================

def parse_pdf_date(value):

    if not value:
        return None

    value = str(value).strip()

    # Example:
    # D:20260809105416+01'00'

    match = re.search(
        r"D:(\d{4})(\d{2})(\d{2})"
        r"(\d{2})?(\d{2})?(\d{2})?",
        value
    )

    if not match:
        return None

    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))

    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    second = int(match.group(6) or 0)

    try:

        return datetime(
            year,
            month,
            day,
            hour,
            minute,
            second
        )

    except ValueError:

        return None


# ============================================================
# TRANSACTION DATE EXTRACTION
# ============================================================

def extract_transaction_dates(file_path):

    dates = []

    try:

        reader = PdfReader(file_path)

        text = ""

        for page in reader.pages:

            try:
                text += "\n" + (page.extract_text() or "")
            except Exception:
                pass

        # ----------------------------------------------------
        # DD.MM.YYYY HH:MM:SS
        # ----------------------------------------------------

        matches = re.findall(
            r"(?i)"
            r"(?:Date\s*(?:de\s*)?(?:transaction|operation)?"
            r"|Transaction\s*Date"
            r"|Date\s*of\s*Transaction"
            r"|Date)"
            r"\s*[:\-]?\s*"
            r"(\d{1,2}[./-]\d{1,2}[./-]\d{4}"
            r"\s+\d{1,2}:\d{2}(?::\d{2})?)",
            text
        )

        # ----------------------------------------------------
        # Generic date fallback
        # ----------------------------------------------------

        if not matches:

            matches = re.findall(
                r"\b"
                r"(\d{1,2}[./-]\d{1,2}[./-]\d{4}"
                r"\s+\d{1,2}:\d{2}(?::\d{2})?)"
                r"\b",
                text
            )

        for value in matches:

            value = value.strip()

            parsed = None

            for fmt in (
                "%d.%m.%Y %H:%M:%S",
                "%d.%m.%Y %H:%M",
                "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M",
                "%d-%m-%Y %H:%M:%S",
                "%d-%m-%Y %H:%M",
            ):

                try:

                    parsed = datetime.strptime(
                        value,
                        fmt
                    )

                    break

                except ValueError:
                    continue

            if parsed:

                dates.append(
                    {
                        "raw": value,
                        "datetime": parsed
                    }
                )

    except Exception:
        pass

    return dates


# ============================================================
# XMP / RAW DATES
# ============================================================

def extract_raw_dates(data):

    creation_dates = re.findall(
        rb"/CreationDate\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    modification_dates = re.findall(
        rb"/ModDate\s*\((.*?)\)",
        data,
        re.DOTALL
    )

    creation = None
    modification = None

    if creation_dates:

        creation = creation_dates[-1].decode(
            "latin-1",
            errors="ignore"
        )

    if modification_dates:

        modification = modification_dates[-1].decode(
            "latin-1",
            errors="ignore"
        )

    return {
        "creation_raw": creation,
        "modification_raw": modification,
        "creation_count": len(creation_dates),
        "modification_count": len(modification_dates),
    }


# ============================================================
# STRUCTURAL FORENSICS
# ============================================================

def analyze_structure(data):

    findings = []

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

    startxref_count = len(
        re.findall(
            rb"\bstartxref\b",
            data
        )
    )

    if startxref_count > 1:

        findings.append(
            f"Multiple startxref sections detected ({startxref_count})"
        )

    # --------------------------------------------------------
    # PREV
    # --------------------------------------------------------

    prev_count = len(
        re.findall(
            rb"/Prev\b",
            data
        )
    )

    if prev_count > 0:

        findings.append(
            f"Previous revision reference detected (/Prev: {prev_count})"
        )

    # --------------------------------------------------------
    # EOF
    # --------------------------------------------------------

    eof_count = len(
        re.findall(
            rb"%%EOF",
            data
        )
    )

    if eof_count > 1:

        findings.append(
            f"Multiple EOF markers detected ({eof_count})"
        )

    # --------------------------------------------------------
    # OBJECTS
    # --------------------------------------------------------

    object_count = len(
        re.findall(
            rb"(?m)^\d+\s+\d+\s+obj\b",
            data
        )
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
    # SIGNATURE
    # --------------------------------------------------------

    has_signature = (
        b"/ByteRange" in data
        or
        b"/FT /Sig" in data
    )

    # --------------------------------------------------------
    # XMP
    # --------------------------------------------------------

    has_xmp = (
        b"<x:xmpmeta" in data
        or
        b"<rdf:RDF" in data
    )

    return {
        "findings": findings,
        "startxref_count": startxref_count,
        "prev_count": prev_count,
        "eof_count": eof_count,
        "object_count": object_count,
        "producer": producer,
        "creator": creator,
        "has_signature": has_signature,
        "has_xmp": has_xmp,
    }


# ============================================================
# CHRONOLOGY FORENSICS
# ============================================================

def check_transaction_chronology(
    file_path,
    metadata,
    raw_dates
):

    findings = []

    transaction_dates = (
        extract_transaction_dates(
            file_path
        )
    )

    creation = parse_pdf_date(
        raw_dates["creation_raw"]
    )

    modification = parse_pdf_date(
        raw_dates["modification_raw"]
    )

    # --------------------------------------------------------
    # TRANSACTION VS CREATION
    # --------------------------------------------------------

    for tx in transaction_dates:

        tx_date = tx["datetime"]

        if creation:

            difference = (
                tx_date - creation
            ).total_seconds()

            # PDF created significantly BEFORE transaction
            if difference > TIME_TOLERANCE_SECONDS:

                days = difference / 86400

                if days >= 1:

                    findings.append(
                        "PDF creation date is "
                        f"{days:.1f} days before transaction date"
                    )

                else:

                    hours = difference / 3600

                    findings.append(
                        "PDF creation date is "
                        f"{hours:.1f} hours before transaction date"
                    )

        # ----------------------------------------------------
        # TRANSACTION VS MODIFICATION
        # ----------------------------------------------------

        if modification:

            difference = (
                tx_date - modification
            ).total_seconds()

            if difference > TIME_TOLERANCE_SECONDS:

                days = difference / 86400

                if days >= 1:

                    findings.append(
                        "PDF modification date is "
                        f"{days:.1f} days before transaction date"
                    )

                else:

                    hours = difference / 3600

                    findings.append(
                        "PDF modification date is "
                        f"{hours:.1f} hours before transaction date"
                    )

    return {
        "findings": findings,
        "transaction_dates": transaction_dates,
        "creation": creation,
        "modification": modification,
    }


# ============================================================
# MAIN FORENSIC ENGINE
# ============================================================

def forensic_analysis(file_path):

    data = read_pdf_bytes(
        file_path
    )

    metadata = get_pdf_metadata(
        file_path
    )

    raw_dates = extract_raw_dates(
        data
    )

    structure = analyze_structure(
        data
    )

    findings = list(
        structure["findings"]
    )

    # --------------------------------------------------------
    # DUPLICATE DATE ENTRIES
    # --------------------------------------------------------

    if raw_dates["creation_count"] > 1:

        findings.append(
            "Multiple CreationDate entries detected"
        )

    if raw_dates["modification_count"] > 1:

        findings.append(
            "Multiple ModDate entries detected"
        )

    # --------------------------------------------------------
    # CREATION VS MODIFICATION
    # --------------------------------------------------------

    creation = parse_pdf_date(
        raw_dates["creation_raw"]
    )

    modification = parse_pdf_date(
        raw_dates["modification_raw"]
    )

    if creation and modification:

        if creation != modification:

            findings.append(
                "CreationDate and ModDate are different"
            )

    # --------------------------------------------------------
    # CHRONOLOGY
    # --------------------------------------------------------

    chronology = check_transaction_chronology(
        file_path,
        metadata,
        raw_dates
    )

    findings.extend(
        chronology["findings"]
    )

    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    unique_findings = []

    for finding in findings:

        if finding not in unique_findings:

            unique_findings.append(
                finding
            )

    findings = unique_findings

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

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
        "raw_dates": raw_dates,
        "chronology": chronology,
    }


# ============================================================
# START
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
    # SIZE
    # --------------------------------------------------------

    if (
        document.file_size
        and
        document.file_size > MAX_FILE_SIZE
    ):

        await update.message.reply_text(
            "❌ File is too large.\n"
            "Maximum size: 50 MB."
        )

        return

    # --------------------------------------------------------
    # NAME
    # --------------------------------------------------------

    filename = (
        document.file_name
        or
        "document.pdf"
    )

    if not filename.lower().endswith(
        ".pdf"
    ):

        await update.message.reply_text(
            "❌ Please send a PDF file."
        )

        return

    processing = await update.message.reply_text(
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
        # PDF HEADER
        # ----------------------------------------------------

        with open(
            temp_path,
            "rb"
        ) as f:

            header = f.read(5)

        if header != b"%PDF-":

            await processing.edit_text(
                "❌ Invalid PDF file."
            )

            return

        # ----------------------------------------------------
        # MIME
        # ----------------------------------------------------

        mime_type, _ = mimetypes.guess_type(
            filename
        )

        if not mime_type:

            mime_type = "application/pdf"

        # ----------------------------------------------------
        # HASH
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
        # SIZE
        # ----------------------------------------------------

        file_size = (
            document.file_size
            or
            os.path.getsize(
                temp_path
            )
        )

        # ----------------------------------------------------
        # OUTPUT
        # ----------------------------------------------------

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

        await processing.edit_text(
            message
        )

    except Exception as error:

        print(
            "FORENSIC ERROR:",
            repr(error)
        )

        try:

            await processing.edit_text(
                "❌ Analysis failed.\n\n"
                f"Error: {str(error)[:500]}"
            )

        except Exception:
            pass

    finally:

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


if __name__ == "__main__":
    main()
