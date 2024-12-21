import matplotlib
matplotlib.use('Agg')

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib.pyplot as plt
import pandas as pd
from io import BytesIO
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        plt.style.use('default')
        self.styles = getSampleStyleSheet()
        
        # Profesjonell fargepalett
        self.brand_colors = {
            'primary': '#2C3E50',    # Mørk blå
            'secondary': '#34495E',   # Litt lysere blå
            'accent': '#3498DB',      # Highlight blå
            'success': '#27AE60',     # Grønn
            'warning': '#F39C12',     # Oransje
            'danger': '#E74C3C',      # Rød
            'light': '#ECF0F1',       # Lys grå
            'dark': '#2C3E50'         # Mørk blå
        }
        
        # Risk farger
        self.risk_colors = {
            'KRITISK': '#E74C3C',     # Rød
            'HØY': '#E67E22',         # Oransje
            'MEDIUM': '#F1C40F',      # Gul
            'LAV': '#2ECC71',         # Grønn
            'UKJENT': '#95A5A6',      # Grå
            'FEIL': '#C0392B'         # Mørk rød
        }
        
        # Forbedrede stiler
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            spaceAfter=40,
            spaceBefore=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor(self.brand_colors['primary']),
            fontName='Helvetica-Bold'
        )
        
        self.heading2_style = ParagraphStyle(
            'CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=20,
            spaceBefore=25,
            spaceAfter=20,
            textColor=colors.HexColor(self.brand_colors['secondary']),
            fontName='Helvetica-Bold'
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            fontSize=12,
            leading=16,
            spaceAfter=12,
            fontName='Helvetica'
        )
        
        # Tabell stiler
        self.table_style = TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.brand_colors['primary'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            
            # Data rows
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor(self.brand_colors['light'])),
            
            # Alternating rows
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), 
             [colors.HexColor(self.brand_colors['light']), colors.white])
        ])

    def add_header_footer(self, canvas, doc):
        """Kombinert metode for header og footer"""
        # Header
        canvas.saveState()
        canvas.setFont('Helvetica-Bold', 10)
        canvas.drawString(doc.leftMargin, doc.height + doc.topMargin + 10, "SOC Analysis Report")
        canvas.drawString(doc.width - 2*inch, doc.height + doc.topMargin + 10, 
                         datetime.now().strftime("%Y-%m-%d %H:%M"))
        canvas.line(doc.leftMargin, doc.height + doc.topMargin + 5, 
                   doc.width + doc.leftMargin, doc.height + doc.topMargin + 5)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        page_num = canvas.getPageNumber()
        text = f"Side {page_num}"
        canvas.drawString(doc.width/2, doc.bottomMargin - 20, text)
        canvas.restoreState()

    def create_executive_summary(self, analyses):
        """Lag en oppsummering av funnene"""
        summary = []
        
        total = len(analyses)
        risk_levels = {
            'KRITISK': 0,
            'HØY': 0,
            'MEDIUM': 0,
            'LAV': 0,
            'UKJENT': 0,
            'FEIL': 0
        }
        
        for analysis in analyses:
            risk_cat = analysis.get('risk_category', 'UKJENT')
            if risk_cat in risk_levels:
                risk_levels[risk_cat] += 1
            else:
                risk_levels['UKJENT'] += 1
        
        summary.append(Paragraph("Executive Summary", self.heading2_style))
        summary.append(Spacer(1, 12))
        
        summary_text = f"""
        Dette er en analyse av {total} URLer skannet i perioden. 
        Av disse ble {risk_levels['KRITISK']} klassifisert som KRITISK risiko,
        {risk_levels['HØY']} som HØY risiko, og {risk_levels['FEIL']} analyser feilet.
        Dette krever oppfølging av {risk_levels['KRITISK'] + risk_levels['HØY']} URLer.
        """
        summary.append(Paragraph(summary_text, self.normal_style))
        
        return summary

    def create_risk_distribution_chart(self, analyses):
        """Lager et kakediagram over risikofordeling"""
        risk_distribution = {
            'KRITISK': 0,
            'HØY': 0,
            'MEDIUM': 0,
            'LAV': 0,
            'UKJENT': 0,
            'FEIL': 0
        }
        
        # Definer fargene direkte som hex-strenger
        color_map = {
            'KRITISK': '#ff8080',
            'HØY': '#ffcccc',
            'MEDIUM': '#ffffcc',
            'LAV': '#ccffcc',
            'UKJENT': '#f2f2f2',
            'FEIL': '#ff0000'
        }
        
        for analysis in analyses:
            risk_cat = analysis.get('risk_category', 'UKJENT')
            if risk_cat in risk_distribution:
                risk_distribution[risk_cat] += 1
            else:
                risk_distribution['UKJENT'] += 1

        plt.style.use('seaborn-v0_8-whitegrid')  # Mer profesjonelt utseende
        
        plt.figure(figsize=(10, 7))  # Større figur
        plt.clf()
        
        # Filtrer ut kategorier med 0 forekomster
        non_zero_cats = {k: v for k, v in risk_distribution.items() if v > 0}
        
        if non_zero_cats:  # Sjekk om det er noen data å vise
            values = list(non_zero_cats.values())
            labels = [f"{cat}\n({count})" for cat, count in non_zero_cats.items()]
            colors = [self.risk_colors[cat] for cat in non_zero_cats.keys()]
            
            patches, texts, autotexts = plt.pie(
                values, 
                labels=labels, 
                colors=colors, 
                autopct='%1.1f%%',
                textprops={'fontsize': 12},  # Større font
                pctdistance=0.85,
                explode=[0.05] * len(values)  # Litt separasjon mellom sektorene
            )
            
            # Forbedret lesbarhet
            plt.setp(autotexts, size=10, weight="bold")
            plt.setp(texts, size=12)
            
            plt.title('Risk Distribution', pad=20, size=14, weight='bold')
        else:
            plt.text(0.5, 0.5, 'No data to display',
                    horizontalalignment='center',
                    verticalalignment='center',
                    fontsize=12)
        
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=300)
        img_buffer.seek(0)
        plt.close('all')
        
        return img_buffer
        
    def create_mitre_techniques_chart(self, analyses):
        """Lager et stolpediagram over mest brukte MITRE-teknikker"""
        technique_counts = {}
        for analysis in analyses:
            if 'mitre_analysis' in analysis and 'techniques' in analysis['mitre_analysis']:
                for tech in analysis['mitre_analysis']['techniques']:
                    technique_counts[tech] = technique_counts.get(tech, 0) + 1
        
        plt.figure(figsize=(10, 6))
        plt.clf()
        
        if technique_counts:
            techniques = list(technique_counts.keys())
            counts = list(technique_counts.values())
            
            plt.bar(techniques, counts, color='#1F4E78')
            plt.xticks(rotation=45, ha='right')
            plt.title('Most Common MITRE ATT&CK Techniques', pad=20)
            plt.tight_layout()
        else:
            plt.text(0.5, 0.5, 'No MITRE techniques found', 
                    horizontalalignment='center', verticalalignment='center')
        
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=300)
        img_buffer.seek(0)
        plt.close('all')
        
        return img_buffer
    
    def test_pdf_generation(self, output_path):
        """Test PDF generation with minimal content"""
        try:
            print("\n=== Testing PDF Generation ===")
            print(f"Output path: {output_path}")
            
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            story = []
            story.append(Paragraph("Test Report", self.title_style))
            
            print("Building PDF...")
            doc.build(story)
            print("PDF build completed")
            
            if os.path.exists(output_path):
                print(f"Test file created successfully at: {output_path}")
                return True
            else:
                print("Test file was not created")
                return False
            
        except Exception as e:
            print(f"\nPDF Test Generation Error:")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def generate_pdf_report(self, analyses, output_path):
        """Genererer en detaljert PDF-rapport med forbedret layout"""
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=50,      # Justerte marger
                leftMargin=50,
                topMargin=60,
                bottomMargin=50
            )
            
            story = []
            
            # Tittel med mer luft
            story.append(Spacer(1, 20))
            story.append(Paragraph("SOC Analysis Report", self.title_style))
            story.append(Spacer(1, 40))
            
            # Executive Summary med bedre spacing
            story.extend(self.create_executive_summary(analyses))
            story.append(Spacer(1, 30))
            
            # Risiko-distribusjonsgraf
            story.append(Paragraph("Risk Distribution", self.heading2_style))
            story.append(Spacer(1, 15))
            risk_chart = self.create_risk_distribution_chart(analyses)
            story.append(Image(risk_chart, width=450, height=300))  # Større graf
            story.append(Spacer(1, 30))
            
            # MITRE ATT&CK analyse
            story.append(Paragraph("MITRE ATT&CK Analysis", self.heading2_style))
            story.append(Spacer(1, 15))
            mitre_chart = self.create_mitre_techniques_chart(analyses)
            story.append(Image(mitre_chart, width=450, height=300))  # Større graf
            story.append(Spacer(1, 30))
            
            # Detaljert analysetabell med bedre formatering
            story.append(Paragraph("Detailed Analysis", self.heading2_style))
            story.append(Spacer(1, 15))
            
            # Tabell med bedre kolonnebredder
            col_widths = [250, 80, 80, 200]  # Justerte kolonnebredder
            table_data = [['URL', 'Risk', 'Score', 'Action Required']]
            for analysis in analyses:
                table_data.append([
                    analysis.get('url', 'N/A'),
                    analysis.get('risk_category', 'N/A'),
                    analysis.get('risk_score', 'N/A'),
                    analysis.get('action_required', 'N/A')
                ])
            
            table = Table(table_data, repeatRows=1, colWidths=col_widths)
            table.setStyle(self.table_style)
            story.append(table)
            
            doc.build(story, onFirstPage=self.add_header_footer, 
                     onLaterPages=self.add_header_footer)
            
            return output_path
            
        except Exception as e:
            print(f"Error in generate_pdf_report: {str(e)}")
            raise