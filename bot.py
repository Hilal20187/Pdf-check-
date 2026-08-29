import os
import hashlib
from pypdf import PdfReader

def forensic_pdf_check(file_path):
    risk_score = 0
    evidence = []
    
    try:
        reader = PdfReader(file_path)
        meta = reader.metadata
    except Exception as e:
        return f"❌ فشل قراءة الملف: {e}"
    
    # استخراج الـ Metadata الأساسية مع حماية من القيم الفارغة
    producer = str(meta.get('/Producer', '') or '')
    creator = str(meta.get('/Creator', '') or '')
    creation_date = str(meta.get('/CreationDate', '') or '')
    mod_date = str(meta.get('/ModDate', '') or '')
    
    producer_lower = producer.lower()
    creator_lower = creator.lower()
    
    # 1. اكتشاف تضارب الـ iText أو إعادة الحفظ بأدوات مختلفة (مثل الملفات المعدلة)
    if 'modified using' in producer_lower or producer_lower.count('itext') > 1:
        risk_score += 50
        evidence.append("⚠️ تم اكتشاف أثر لتعدد الإصدارات أو التعديل بمكتبة دمج (iText Conflict)، مما يدل على أن الملف معدل.")
    
    # 2. كشف أدوات التعديل الشائعة عبر الإنترنت وبرامج التحرير
    suspicious_tools = ['ilovepdf', 'smallpdf', 'sejda', 'adobe acrobat', 'pdfme', 'python']
    for tool in suspicious_tools:
        if tool in producer_lower or tool in creator_lower:
            risk_score += 30
            evidence.append(f"⚠️ وُجد أثر لأداة تحرير أو مكتبة شائعة: {tool.upper()}")

    # 3. اختلاف تاريخ الإنشاء عن تاريخ التعديل
    if creation_date and mod_date and creation_date != mod_date:
        risk_score += 15
        evidence.append("⚠️ اختلاف بين تاريخ الإنشاء (CreationDate) وتاريخ التعديل (ModDate).")

    # تحديد المستوى النهائي للخطورة
    if risk_score >= 50:
        risk_level = "🔴 HIGH RISK (مؤشرات تلاعب واضحة)"
    elif risk_score > 0:
        risk_level = "🟡 MEDIUM INDICATIONS (يحذر من وجود تعديل)"
    else:
        risk_level = "🟢 LOW INDICATIONS (لا توجد مؤشرات قوية)"

    # حساب الـ SHA-256 لأي ملف PDF يتم تمريره
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # صياغة التقرير النهائي
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
Risk Score لا يعني أن التزوير مثبت قانونيًا.
By LEX
"""
    return report
