import os
import tempfile
import logging

import fitz
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# =========================================================
# CONFIG
# =========================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN غير موجود في Environment Variables")

# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("LEX")


# =========================================================
# START
# =========================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "LEX PDF Bot خدام\n\n"
        "أرسل PDF للفحص."
    )


# =========================================================
# PDF ANALYSIS
# =========================================================

def analyze_pdf(path):

    score = 0

    try:

        # -------------------------------------------------
        # Open PDF
        # -------------------------------------------------

        doc = fitz.open(path)

        if doc.page_count == 0:
            return "مشبوه"

        # -------------------------------------------------
        # Raw bytes
        # -------------------------------------------------

        with open(path, "rb") as f:
            data = f.read()

        # -------------------------------------------------
        # Basic PDF validation
        # -------------------------------------------------

        if not data.startswith(b"%PDF-"):
            score += 100

        if b"%%EOF" not in data[-8192:]:
            score += 40

        # -------------------------------------------------
        # PDF objects
        # -------------------------------------------------

        if b" obj" not in data:
            score += 30

        # -------------------------------------------------
        # Broken stream structure
        # -------------------------------------------------

        streams = data.count(b"stream")
        endstreams = data.count(b"endstream")

        if streams != endstreams:
            score += 35

        # -------------------------------------------------
        # Broken xref
        # -------------------------------------------------

        if b"startxref" not in data:
            score += 25

        # -------------------------------------------------
        # IMPORTANT:
        #
        # ModDate is NOT considered proof of forgery.
        # Images are NOT considered proof.
        # Fonts are NOT considered proof.
        # Streams are NOT considered proof.
        #
        # BaridiMob PDFs can legitimately contain them.
        # -------------------------------------------------

        # -------------------------------------------------
        # Inspect pages
        # -------------------------------------------------

        for page in doc:

            # Make sure page can actually be rendered
            page.get_pixmap(
                matrix=fitz.Matrix(0.5, 0.5),
                alpha=False
            )

            # Read text
            page.get_text("text")

            # Read images
            page.get_images(full=True)

            # Read fonts
            page.get_fonts(full=True)

        # -------------------------------------------------
        # Metadata
        # -------------------------------------------------

        metadata = doc.metadata or {}

        # We only inspect it.
        # We DO NOT automatically mark the PDF fake.

        _creation = metadata.get("creationDate")
        _modified = metadata.get("modDate")
        _producer = metadata.get("producer")
        _creator = metadata.get("creator")

        # Prevent unused-variable problems
        _ = (
            _creation,
            _modified,
            _producer,
            _creator,
        )

        doc.close()

        # -------------------------------------------------
        # FINAL RESULT
        # -------------------------------------------------

        if score >= 25:
            return "مشبوه"

        return "صحيح"

    except Exception as e:

        logger.exception(
            "PDF analysis failed: %s",
            e
        )

        return "مشبوه"


# =========================================================
# PDF HANDLER
# =========================================================

async def pdf_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE
):

    message = update.effective_message

    if not message:
        return

    document = message.document

    if not document:
        return

    filename = document.file_name or ""

    # -----------------------------------------------------
    # PDF ONLY
    # -----------------------------------------------------

    if not filename.lower().endswith(".pdf"):

        await message.reply_text(
            "أرسل PDF فقط."
        )

        return

    temp_path = None

    try:

        # -------------------------------------------------
        # Create temporary file
        # -------------------------------------------------

        with tempfile.NamedTemporaryFile(
            suffix=".pdf",
            delete=False
        ) as tmp:

            temp_path = tmp.name

        # -------------------------------------------------
        # Download
        # -------------------------------------------------

        telegram_file = await context.bot.get_file(
            document.file_id
        )

        await telegram_file.download_to_drive(
            custom_path=temp_path
        )

        logger.info(
            "PDF received: %s",
            filename
        )

        # -------------------------------------------------
        # Analyze
        # -------------------------------------------------

        result = analyze_pdf(temp_path)

        # -------------------------------------------------
        # USER OUTPUT
        # -------------------------------------------------

        await message.reply_text(
            f"{result}\n\nBy LEX"
        )

    except Exception as e:

        logger.exception(
            "Telegram PDF error: %s",
            e
        )

        await message.reply_text(
            "مشبوه\n\nBy LEX"
        )

    finally:

        # -------------------------------------------------
        # Delete temporary PDF
        # -------------------------------------------------

        if temp_path:

            try:
                os.remove(temp_path)
            except Exception:
                pass


# =========================================================
# ERROR HANDLER
# =========================================================

async def error_handler(
    update: object,
    context: ContextTypes.DEFAULT_TYPE
):

    logger.exception(
        "Telegram error:",
        exc_info=context.error
    )


# =========================================================
# MAIN
# =========================================================

def main():

    print("================================")
    print("LEX PDF BOT")
    print("Starting...")
    print("================================")

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .build()
    )

    # /start
    application.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    # /hello
    application.add_handler(
        CommandHandler(
            "hello",
            start
        )
    )

    # PDF
    application.add_handler(
        MessageHandler(
            filters.Document.PDF,
            pdf_handler
        )
    )

    # Errors
    application.add_error_handler(
        error_handler
    )

    print("LEX PDF BOT IS RUNNING")

    application.run_polling(
        drop_pending_updates=True
    )


if __name__ == "__main__":
    main() 
