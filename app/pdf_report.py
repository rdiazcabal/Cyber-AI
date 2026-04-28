import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def generate_pdf_report(report):
    buffer = BytesIO()

    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 50

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Cyber-AI SOC Report")

    y -= 30
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Report ID: {report.id}")

    y -= 18
    pdf.drawString(50, y, f"Title: {report.title}")

    y -= 18
    pdf.drawString(50, y, f"Risk Score: {report.risk_score}")

    y -= 18
    pdf.drawString(50, y, f"Created At: {report.created_at}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Analysis Summary")

    y -= 20
    pdf.setFont("Helvetica", 8)

    result = json.loads(report.result_json)

    text = json.dumps(result, indent=2)

    for line in text.splitlines():
        if y < 60:
            pdf.showPage()
            y = height - 50
            pdf.setFont("Helvetica", 8)

        pdf.drawString(50, y, line[:110])
        y -= 11

    pdf.save()
    buffer.seek(0)

    return buffer