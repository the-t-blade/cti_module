"""
Professional PDF report generator for Analyst Dashboard.
Generates well-structured A4 reports with logo, headers, and data visualizations.
"""

import io
from datetime import datetime
from django.http import HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    Image, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os


class AnalystReportGenerator:
    """Generate professional PDF reports for analyst performance"""
    
    # Color scheme matching your CTI platform
    COLORS = {
        'primary': colors.HexColor('#0891b2'),      # Cyan
        'secondary': colors.HexColor('#3b82f6'),    # Blue
        'success': colors.HexColor('#22c55e'),      # Green
        'warning': colors.HexColor('#eab308'),      # Yellow
        'danger': colors.HexColor('#ef4444'),       # Red
        'dark': colors.HexColor('#1f2937'),         # Dark Gray
        'gray': colors.HexColor('#6b7280'),         # Gray
        'light': colors.HexColor('#f3f4f6'),        # Light Gray
        'white': colors.HexColor('#ffffff'),
    }
    
    @staticmethod
    def generate(analyst_data, analyst, request):
        """Generate PDF report for analyst"""
        
        # Create buffer for PDF
        buffer = io.BytesIO()
        
        # Use landscape for better table display
        doc = SimpleDocTemplate(
            buffer,
            pagesize=landscape(A4),
            rightMargin=0.5*cm,
            leftMargin=0.5*cm,
            topMargin=0.75*cm,
            bottomMargin=0.75*cm
        )
        
        # Story (content) list
        story = []
        
        # Register font (optional - uses default if not available)
        try:
            pdfmetrics.registerFont(TTFont('Helvetica', 'Helvetica'))
        except:
            pass
        
        # Styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=AnalystReportGenerator.COLORS['primary'],
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        )
        
        heading1_style = ParagraphStyle(
            'CustomHeading1',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=AnalystReportGenerator.COLORS['secondary'],
            spaceBefore=15,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        )
        
        heading2_style = ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=AnalystReportGenerator.COLORS['dark'],
            spaceBefore=10,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontSize=10,
            textColor=AnalystReportGenerator.COLORS['gray'],
            alignment=TA_LEFT,
            fontName='Helvetica'
        )
        
        # ============================================================
        # HEADER SECTION with Logo
        # ============================================================
        
        # Header table
        header_data = []
        
        # Try to add logo if exists
        logo_path = os.path.join(os.path.dirname(__file__), 'static', 'images', 'zimcert_logo.png')
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=1.5*cm, height=1.5*cm)
            header_data.append([logo, '', ''])
        
        # Title and date
        header_data.append([
            Paragraph("ZIMBABWE NATIONAL CERT", ParagraphStyle(
                'HeaderTitle',
                parent=styles['Normal'],
                fontSize=12,
                textColor=AnalystReportGenerator.COLORS['primary'],
                alignment=TA_LEFT,
                fontName='Helvetica-Bold'
            )),
            '',
            Paragraph(f"Date: {timezone.now().strftime('%Y-%m-%d %H:%M')}", 
                     ParagraphStyle('DateStyle', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT))
        ])
        
        header_table = Table(header_data, colWidths=[4*cm, 10*cm, 4*cm])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(header_table)
        
        # Separator line
        story.append(HRFlowable(width="100%", thickness=1, color=AnalystReportGenerator.COLORS['primary']))
        story.append(Spacer(1, 10))
        
        # ============================================================
        # MAIN TITLE
        # ============================================================
        
        story.append(Paragraph("Analyst Performance Report", title_style))
        story.append(Spacer(1, 5))
        
        # Analyst info
        analyst_info = f"""
        <para alignment="center">
        <b>Analyst:</b> {analyst.username} | 
        <b>Name:</b> {analyst.get_full_name() or analyst.username} | 
        <b>Email:</b> {analyst.email or 'N/A'}
        </para>
        """
        story.append(Paragraph(analyst_info, body_style))
        story.append(Spacer(1, 15))
        
        # ============================================================
        # KEY METRICS CARDS (as table)
        # ============================================================
        
        story.append(Paragraph("Key Performance Indicators", heading1_style))
        story.append(Spacer(1, 5))
        
        # Metrics table - 4 columns
        metrics_data = [
            [
                AnalystReportGenerator._create_metric_cell("Total Alerts", analyst_data['alerts_handled'], AnalystReportGenerator.COLORS['primary']),
                AnalystReportGenerator._create_metric_cell("Resolution Rate", f"{analyst_data['resolution_rate']}%", AnalystReportGenerator.COLORS['success']),
                AnalystReportGenerator._create_metric_cell("Avg Response", f"{analyst_data['avg_response_hours']}h", AnalystReportGenerator.COLORS['warning']),
                AnalystReportGenerator._create_metric_cell("Daily Avg", f"{analyst_data['daily_avg']}", AnalystReportGenerator.COLORS['secondary']),
            ]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[5.5*cm, 5.5*cm, 5.5*cm, 5.5*cm])
        metrics_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (0, 0), AnalystReportGenerator.COLORS['primary']),
            ('BACKGROUND', (1, 0), (1, 0), AnalystReportGenerator.COLORS['success']),
            ('BACKGROUND', (2, 0), (2, 0), AnalystReportGenerator.COLORS['warning']),
            ('BACKGROUND', (3, 0), (3, 0), AnalystReportGenerator.COLORS['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 15))
        
        # ============================================================
        # DETAIL STATISTICS TABLE
        # ============================================================
        
        story.append(Paragraph("Alert Statistics", heading1_style))
        story.append(Spacer(1, 5))
        
        stats_data = [
            ['Metric', 'Value', 'Status'],
            ['Alerts Handled', str(analyst_data['alerts_handled']), 
             Paragraph('<font color="green">✓ Active</font>', body_style)],
            ['Resolved', str(analyst_data['alerts_resolved']), 
             Paragraph('<font color="green">✓ Completed</font>', body_style)],
            ['Acknowledged', str(analyst_data['alerts_acknowledged']), 
             Paragraph('<font color="orange">⏳ Pending</font>', body_style)],
            ['Investigating', str(analyst_data['alerts_investigating']), 
             Paragraph('<font color="blue">🔍 In Progress</font>', body_style)],
            ['Campaigns Involved', str(analyst_data['campaigns_involved']), 
             Paragraph('<font color="purple">🎯 Active</font>', body_style)],
            ['Indicators Created', str(analyst_data['indicators_created']), 
             Paragraph('<font color="cyan">📊 Contributed</font>', body_style)],
        ]
        
        stats_table = Table(stats_data, colWidths=[5*cm, 4*cm, 9*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), AnalystReportGenerator.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), AnalystReportGenerator.COLORS['light']),
            ('GRID', (0, 0), (-1, -1), 0.5, AnalystReportGenerator.COLORS['gray']),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 15))
        
        # ============================================================
        # SEVERITY DISTRIBUTION (as text table)
        # ============================================================
        
        story.append(Paragraph("Alert Severity Distribution", heading1_style))
        story.append(Spacer(1, 5))
        
        severity_data = [['Severity', 'Count', 'Percentage', 'Visual']]
        total = sum(s['count'] for s in analyst_data['severity_distribution'])
        
        severity_colors = {
            'Critical': AnalystReportGenerator.COLORS['danger'],
            'High': AnalystReportGenerator.COLORS['warning'],
            'Medium': AnalystReportGenerator.COLORS['secondary'],
            'Low': AnalystReportGenerator.COLORS['success'],
        }
        
        for item in analyst_data['severity_distribution']:
            severity = item['severity']
            count = item['count']
            percentage = round((count / total) * 100, 1) if total > 0 else 0
            # Create visual bar
            bar_width = int(percentage * 2)  # Scale for visual
            bar = '█' * min(bar_width, 40) + '░' * (40 - min(bar_width, 40))
            
            severity_data.append([
                severity, 
                str(count), 
                f"{percentage}%",
                Paragraph(f'<font face="Courier">{bar}</font>', body_style)
            ])
        
        severity_table = Table(severity_data, colWidths=[4*cm, 3*cm, 3*cm, 8*cm])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), AnalystReportGenerator.COLORS['dark']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, AnalystReportGenerator.COLORS['gray']),
            ('BACKGROUND', (0, 1), (0, -1), AnalystReportGenerator.COLORS['light']),
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 15))
        
        # ============================================================
        # TOP THREAT ACTORS
        # ============================================================
        
        if analyst_data['top_threat_actors']:
            story.append(Paragraph("Top Threat Actors", heading1_style))
            story.append(Spacer(1, 5))
            
            actor_data = [['Threat Actor', 'Count']]
            for actor in analyst_data['top_threat_actors']:
                actor_data.append([actor.get('threat_actor', 'Unknown'), str(actor.get('count', 0))])
            
            actor_table = Table(actor_data, colWidths=[10*cm, 8*cm])
            actor_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), AnalystReportGenerator.COLORS['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, AnalystReportGenerator.COLORS['gray']),
            ]))
            story.append(actor_table)
            story.append(Spacer(1, 15))
        
        # ============================================================
        # FOOTER
        # ============================================================
        
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=0.5, color=AnalystReportGenerator.COLORS['gray']))
        
        footer_text = f"""
        <para alignment="center" fontsize="8">
        Zimbabwe National CERT - Cyber Threat Intelligence Platform<br/>
        Report generated on {timezone.now().strftime('%Y-%m-%d at %H:%M:%S')}<br/>
        This report is confidential and for authorized use only.
        </para>
        """
        story.append(Paragraph(footer_text, body_style))
        
        # Build PDF
        doc.build(story)
        
        # Get PDF value
        pdf = buffer.getvalue()
        buffer.close()
        
        # Create HTTP response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="analyst_report_{analyst.username}_{timezone.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        response.write(pdf)
        
        return response
    
    @staticmethod
    def _create_metric_cell(label, value, bg_color):
        """Create a formatted metric cell for the PDF"""
        from reportlab.platypus import Paragraph
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        
        style = ParagraphStyle(
            'MetricStyle',
            fontSize=14,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        label_style = ParagraphStyle(
            'MetricLabelStyle',
            fontSize=9,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Helvetica'
        )
        
        content = [
            Paragraph(str(value), style),
            Paragraph(str(label), label_style)
        ]
        
        return content