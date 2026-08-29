import os
import hashlib
import telebot
from pypdf import PdfReader

# حط التوكن تاع بوتك هنا أو خليه يقرأه من Environment Variables في Railway
TOKEN = os.getenv("BOT_TOKEN", "حط_التوكن_هنا_إذا_ماكش_دايرها_في_Railway")
bot = telebot.TeleBot(TOKEN)

def forensic_pdf_check(file_path):
    risk_score = 0
    evidence = []
    
    try:
        reader = PdfReader(file_path)
        meta = reader.metadata
    except Exception as e:
        return f"❌ فشل قراءة الملف: {e}"
    
    producer = str(meta.get('/Producer', '') or '')
    creator = str(meta.get('/Creator', '') or '')
    creation_date = str(meta.get('/CreationDate', '') or '')
    mod_date = str(meta.get('/ModDate', '') or '')
    
    producer_lower = producer.lower()
    creator_lower = creator.lower()
    
    if 'modified using' in producer_lower or producer_lower.count('itext') > 1:
        risk_score += 50
        evidence.append("⚠️ تم اكتشاف أثر لتعدد الإصدارات أو التعديل بمكتبة دمج (iText Conflict)، مما يدل على أن الملف معدل.")
    
    suspicious_tools = ['ilovepdf', 'smallpdf', 'sejda', 'adobe acrobat', 'pdfme', 'python']
    for tool in suspicious_tools:
        if tool in producer_lower or tool in creator_lower:
            risk_score += 30
            evidence.append(f"⚠️ وُجد أثر لأداة تحرير أو مكتبة شائعة: {tool.upper()}")

    if creation_date and mod_date and creation_date != mod_date:
        risk_score += 15
        evidence.append("⚠️ اختلاف بين تاريخ الإنشاء وتاريخ التعديل.")

    if risk_score >= 50:
        risk_level = "🔴 HIGH RISK (مؤشرات تلاعب واضحة)"
    elif risk_score > 0:
        risk_level = "🟡 MEDIUM INDICATIONS (يحذر من وجود تعديل)"
    else:
        risk_level = "🟢 LOW INDICATIONS (لا توجد مؤشرات قوية)"

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    report = f"""
🔎 **LEX PDF FORENSIC PRO v3**

📄 **الملف:** {os.path.basename(file_path)}
📑 **الصفحات:** {len(reader.pages)}
📊 **Risk Score:** {min(risk_score, 100)}/100
📌 **المستوى:** {risk_level}

📝 **METADATA**
• Producer: `{producer or 'غير موجود'}`
• Creator: `{creator or 'غير موجود'}`

📅 **DATES**
• CreationDate: `{creation_date or 'غير موجود'}`
• ModDate: `{mod_date or 'غير موجود'}`

⚠️ **EVIDENCE**
"""
    if evidence:
        for item in evidence:
            report += f"• {item}\n"
    else:
        report += "• لا توجد مؤشرات قوية.\n"

    report += f"""
🔐 **SHA-256**
`{file_hash}`

⚠️ **IMPORTANT**
هذه أداة PDF forensic تقنية.
By LEX
"""
    return report

# استقبال رسائل الـ PDF من المستخدم
@bot.message_handler(content_types=['document'])
def handle_pdf(message):
    try:
        # التحقق إذا كان الملف PDF فعلاً
        if not message.document.file_name.endswith('.pdf'):
            bot.reply_to(message, "❌ أرسل ملف PDF صالحاً من فضلك.")
            return
            
        bot.reply_to(message, "🔍 جاري فحص الملف تقنياً...")
        
        # تحميل الملف من سرفرات تيليجرام
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        local_filename = message.document.file_name
        with open(local_filename, 'wb') as new_file:
            new_file.write(downloaded_file)
            
        # تشغيل الفحص
        result_report = forensic_pdf_check(local_filename)
        
        # إرسال التقرير للمستخدم
        bot.send_message(message.chat.id, result_report, parse_mode="Markdown")
        
        # حذف الملف المحلي لتفريغ المساحة
        if os.path.exists(local_filename):
            os.remove(local_filename)
            
    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ أثناء معالجة الملف: {e}")

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "مرحباً بك في LEX PDF Forensic Bot 🔎\nأرسل أي ملف PDF وسأقوم بفحصه لك فوراً.")

if __name__ == "__main__":
    print("Bot is running...")
    bot.infinity_polling()
