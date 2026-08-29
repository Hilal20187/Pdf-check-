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
        return {"error": f"فشل قراءة الملف: str(e)}"}
    
    # استخراج الـ Metadata الأساسية
    producer = str(meta.get('/Producer', '') or '')
    creator = str(meta.get('/Creator', '') or '')
    creation_date = str(meta.get('/CreationDate', '') or '')
    mod_date = str(meta.get('/ModDate', '') or '')
    
    # 1. فحص تضارب وتعدد مكتبات الـ Producer (خطير جداً)
    producer_lower = producer.lower()
    if 'modified using' in producer_lower or producer_lower.count('itext') > 1 or 'iText' in producer and 'iText' in producer[producer.find('iText')+5:]:
        risk_score += 45
        evidence.append(f"⚠️ تم رصد تضارب أو دمج إصدارات لمكتبات التعديل في الـ Producer: {producer}")
    
    # 2. فحص تطابق أو تضارب التواريخ
    if creation_date and mod_date and creation_date != mod_date:
        risk_score += 15
        evidence.append("⚠️ اختلاف بين تاريخ الإنشاء (CreationDate) وتاريخ التعديل (ModDate).")

    # 3. فحص وجود أدوات تعديل شائعة (مثل سكريبتات بايثون أو أدوات أونلاين)
    suspicious_tools = ['ilovepdf', 'smallpdf', 'adobe acrobat xi', 'python', 'pdfme', 'sejda']
    full_meta_str = (producer + creator).lower()
    for tool in suspicious_tools:
        if tool in full_meta_str:
            risk_score += 25
            evidence.append(f"⚠️ وُجد أثر لأداة تعديل شهيرة أو سكريبت: {tool.upper()}")

    # تحديد مستوى الخطورة بناءً على النتيجة النهائية
    if risk_score >= 50:
        risk_level = "🔴 HIGH RISK (مؤشرات تلاعب واضحة)"
    elif risk_score > 0:
        risk_level = "🟡 MEDIUM / LOW INDICATIONS (يحتاج تدقيق يدوي)"
    else:
        risk_level = "🟢 LOW INDICATIONS (لا توجد مؤشرات قوية)"

    # حساب الـ SHA-256 للملف
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # تجهيز التقرير النهائي للbot
    report = f"""
🔎 **LEX PDF FORENSIC PRO v3 (Updated)**

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

⚠️ **EVIDENCE & FINDINGS**
"""
    if evidence:
        for item in evidence:
            report += f"{item}\n"
    else:
        report += "• لا توجد مؤشرات قوية.\n"

    report += f"""
🔐 **SHA-256**
`{file_hash}`
"""
    return report

# مثال على الاستخدام:
# print(forensic_pdf_check("MyFinReport (9).pdf"))
 
