"""
Executive PDF Incident Report Generator for NetraShield SOC 2.4.0
Renders a clean, Swiss-editorial PDF summary with Executive KPIs, Severity Breakdown,
MITRE ATT&CK coverage, Incident Dossiers, and Containment Audit History.
"""

import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_executive_pdf_report(
    incidents: List[Dict[str, Any]],
    kpis: Any = None,
    audit_logs: Optional[List[Dict[str, Any]]] = None
) -> bytes:
    if isinstance(kpis, list) and audit_logs is None:
        audit_logs = kpis
        kpis = None
    if not isinstance(kpis, dict):
        kpis = None

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Swiss-editorial styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#111113")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#52525B")
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#111113"),
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "TableBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#27272A")
    )
    body_bold = ParagraphStyle(
        "TableBodyBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#111113")
    )

    story = []

    # 1. Header Block
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph("NetraShield SOC 2.4.0", title_style))
    story.append(Paragraph(f"Executive Threat Triage & Incident Response Report · Generated {now_str}", subtitle_style))
    story.append(Spacer(1, 14))

    # Calculate KPIs if not passed
    total_events = kpis.get("total_events", len(incidents)) if kpis else len(incidents)
    critical_alerts = len([i for i in incidents if i.get("severity") == "CRITICAL"])
    high_alerts = len([i for i in incidents if i.get("severity") == "HIGH"])
    medium_alerts = len([i for i in incidents if i.get("severity") == "MEDIUM"])
    low_alerts = len([i for i in incidents if i.get("severity") == "LOW"])
    avg_risk = sum(float(i.get("risk_score", 0)) for i in incidents) / max(len(incidents), 1)

    # 2. KPI Summary Table
    story.append(Paragraph("Executive Telemetry & Correlation Summary", heading_style))
    kpi_data = [
        ["Total Incidents", "Critical", "High", "Medium", "Low", "Average Risk Score"],
        [
            str(len(incidents)),
            str(critical_alerts),
            str(high_alerts),
            str(medium_alerts),
            str(low_alerts),
            f"{avg_risk:.1f} / 100"
        ]
    ]
    t_kpi = Table(kpi_data, colWidths=[90, 75, 75, 75, 75, 150])
    t_kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F4F4F5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#18181B")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E4E4E7")),
    ]))
    story.append(t_kpi)
    story.append(Spacer(1, 16))

    # 3. Top Correlated Incidents Table
    story.append(Paragraph(f"Prioritized Incident Queue (Top {min(len(incidents), 12)} Dossiers)", heading_style))
    inc_rows = [
        ["Alert ID", "Host", "Severity", "Risk", "MITRE", "Detection Title", "Status"]
    ]
    for inc in incidents[:12]:
        inc_rows.append([
            Paragraph(inc.get("alert_id", ""), body_bold),
            Paragraph(inc.get("host", ""), body_style),
            Paragraph(inc.get("severity", ""), body_bold),
            Paragraph(f"{float(inc.get('risk_score', 0)):.1f}", body_style),
            Paragraph(inc.get("mitre_id", "T1027"), body_style),
            Paragraph(inc.get("detection_title", "")[:35], body_style),
            Paragraph(inc.get("status", "Open"), body_style)
        ])

    t_inc = Table(inc_rows, colWidths=[70, 75, 55, 45, 60, 175, 60])
    t_inc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18181B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#FFFFFF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E4E4E7")),
    ]))
    story.append(t_inc)
    story.append(Spacer(1, 16))

    # 4. Containment Audit History (if available)
    if audit_logs:
        story.append(Paragraph(f"Containment & Remediation Audit Ledger ({len(audit_logs[:6])} Records)", heading_style))
        audit_rows = [["Audit ID", "Incident ID", "Action Type", "Target Entity", "Executed At", "Status"]]
        for a in audit_logs[:6]:
            audit_rows.append([
                Paragraph(a.get("audit_id", ""), body_style),
                Paragraph(a.get("incident_id", ""), body_style),
                Paragraph(a.get("action_type", ""), body_bold),
                Paragraph(a.get("target_entity", "")[:24], body_style),
                Paragraph(a.get("executed_at", "")[:19].replace("T", " "), body_style),
                Paragraph(a.get("new_status", "Contained"), body_style),
            ])
        t_audit = Table(audit_rows, colWidths=[80, 80, 110, 110, 100, 60])
        t_audit.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F4F4F5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#18181B")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E4E4E7")),
        ]))
        story.append(t_audit)
        story.append(Spacer(1, 16))

    # 5. Footer notice
    footer_text = (
        "CONFIDENTIAL & PROPRIETARY — Generated by NetraShield SOC 2.4.0 Blue-Team Defense Workbench. "
        "All telemetry evaluated in local offline enclave."
    )
    story.append(Paragraph(footer_text, subtitle_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
