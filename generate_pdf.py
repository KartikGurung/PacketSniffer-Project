import os
import sys
import subprocess

# Auto-install reportlab if missing
try:
    import reportlab
except ImportError:
    print("Installing required PDF library (reportlab)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    A canvas that enables dynamic page counting ("Page X of Y")
    and adds running headers/footers to all pages except the cover page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Suppress headers and footers on the cover page (Page 1)
        if self._pageNumber == 1:
            return
            
        self.saveState()
        
        # Color definitions
        text_color = colors.HexColor("#64748b")
        line_color = colors.HexColor("#cbd5e1")
        
        # 1. Running Header
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e3a8a")) # Dark blue
        self.drawString(54, 745, "APEX SNIFFER")
        
        self.setFont("Helvetica", 8)
        self.setFillColor(text_color)
        self.drawRightString(558, 745, "Academic Project Report — Threat Intelligence")
        
        # Header Line
        self.setStrokeColor(line_color)
        self.setLineWidth(0.5)
        self.line(54, 737, 558, 737)
        
        # 2. Running Footer
        self.line(54, 52, 558, 52)
        
        self.setFont("Helvetica", 8)
        self.setFillColor(text_color)
        self.drawString(54, 38, "Author: Dashmeet Singh | CS & Engineering")
        
        # Dynamic Page Counter
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 38, page_text)
        
        self.restoreState()

def build_pdf(md_filepath, pdf_filepath):
    print(f"Reading project report from: {md_filepath}...")
    if not os.path.exists(md_filepath):
        print(f"Error: {md_filepath} does not exist.")
        return

    # Set up document template with 0.75 in (54 pt) margins
    # Top and bottom margins are increased to make space for headers/footers
    doc = SimpleDocTemplate(
        pdf_filepath,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )

    # Styles
    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#1e3a8a")   # Deep Blue
    c_dark = colors.HexColor("#0f172a")      # Dark Slate
    c_muted = colors.HexColor("#334155")     # Cool Slate
    
    # Modify default styles in-place or add unique custom styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=32,
        leading=38,
        textColor=c_primary,
        alignment=0, # Left aligned
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=c_muted,
        spaceAfter=30
    )
    
    metadata_style = ParagraphStyle(
        'CoverMetadata',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=c_primary,
        spaceAfter=8
    )

    h1_style = ParagraphStyle(
        'RepH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=c_primary,
        spaceBefore=22,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'RepH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'RepBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=15,
        textColor=c_dark,
        spaceAfter=8
    )
    
    bullet_style = ParagraphStyle(
        'RepBullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=c_dark,
        leftIndent=18,
        firstLineIndent=-10,
        spaceAfter=5
    )
    
    code_style = ParagraphStyle(
        'RepCode',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # ==========================================================
    # COVER PAGE
    # ==========================================================
    story.append(Spacer(1, 120))
    story.append(Paragraph("APEX SNIFFER", title_style))
    story.append(Paragraph("Real-Time Network Packet Sniffer & Anomaly Detection System", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=4, color=c_primary, spaceAfter=40))
    
    story.append(Spacer(1, 100))
    story.append(Paragraph("ACADEMIC PROJECT REPORT", metadata_style))
    story.append(Paragraph("<b>Course:</b> B.Tech - Computer Science & Engineering", ParagraphStyle('CoverText', parent=body_style, textColor=c_muted)))
    story.append(Paragraph("<b>Author:</b> Dashmeet Singh", ParagraphStyle('CoverText', parent=body_style, textColor=c_muted)))
    story.append(Paragraph("<b>Scope:</b> Intrusion Detection System & Protocol Dissecting Core", ParagraphStyle('CoverText', parent=body_style, textColor=c_muted)))
    story.append(Paragraph("<b>Submission Date:</b> June 2026", ParagraphStyle('CoverText', parent=body_style, textColor=c_muted)))
    story.append(PageBreak())

    # ==========================================================
    # PARSING REPORT MARKDOWN
    # ==========================================================
    with open(md_filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_code_block = False
    code_content = []

    for line in lines:
        stripped = line.strip()

        # Handle Code Blocks
        if stripped.startswith("```"):
            if in_code_block:
                # Close code block
                story.append(Paragraph("<br/>".join(code_content), code_style))
                code_content = []
                in_code_block = False
            else:
                in_code_block = True
            continue

        if in_code_block:
            # Escape HTML characters inside code block
            escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>").replace(" ", "&nbsp;")
            code_content.append(escaped)
            continue

        # Skip cover page elements already rendered
        if stripped.startswith("# Project Report") or stripped.startswith("**Academic Final Year") or stripped.startswith("**Field") or stripped.startswith("**Author"):
            continue

        # Page Breaks (represented as --- in markdown)
        if stripped == "---":
            story.append(PageBreak())
            continue

        # Headings
        if stripped.startswith("# "):
            text = stripped[2:]
            story.append(Paragraph(text, h1_style))
        elif stripped.startswith("## "):
            text = stripped[3:]
            story.append(Paragraph(text, h1_style))
        elif stripped.startswith("### "):
            text = stripped[4:]
            story.append(Paragraph(text, h2_style))
            
        # Bullet Points
        elif stripped.startswith("- ") or stripped.startswith("* "):
            text = stripped[2:]
            # basic bold parser (**text** to <b>text</b>)
            text = text.replace("**", "<b>", 1).replace("**", "</b>", 1)
            story.append(Paragraph(f"&bull; {text}", bullet_style))
            
        # Paragraphs
        elif stripped:
            text = stripped
            # basic bold parser (**text** to <b>text</b>)
            # handle multiple occurrences
            while "**" in text:
                text = text.replace("**", "<b>", 1).replace("**", "</b>", 1)
            story.append(Paragraph(text, body_style))
        else:
            story.append(Spacer(1, 6))

    # Build the document
    print(f"Building PDF: {pdf_filepath}...")
    doc.build(story, canvasmaker=NumberedCanvas)
    print("PDF build successful!")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    md_file = os.path.join(base_dir, "project_report.md")
    pdf_file = os.path.join(base_dir, "Apex_Sniffer_Project_Report.pdf")
    build_pdf(md_file, pdf_file)
