from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ==========================================================
# Generate Security PDF
# ==========================================================

def generate_security_pdf(report):
    """
    Generate a professional PDF security report
    using ECDP security report data.
    """

    buffer = BytesIO()


    # ======================================================
    # PDF Document
    # ======================================================

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )


    # ======================================================
    # Styles
    # ======================================================

    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(
        "ECDPTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=8
    )


    subtitle_style = ParagraphStyle(
        "ECDPSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=15
    )


    heading_style = ParagraphStyle(
        "ECDPHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=8
    )


    body_style = ParagraphStyle(
        "ECDPBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )


    small_style = ParagraphStyle(
        "ECDPSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=10
    )


    story = []


    # ======================================================
    # Report Header
    # ======================================================

    story.append(
        Paragraph(
            "Enterprise Cyber Defense Platform",
            title_style
        )
    )


    story.append(
        Paragraph(
            "Security Operations Center Report",
            subtitle_style
        )
    )


    story.append(
        Paragraph(
            f"<b>Generated:</b> "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            body_style
        )
    )


    story.append(
        Spacer(1, 12)
    )


    # ======================================================
    # 1. Security Posture
    # ======================================================

    story.append(
        Paragraph(
            "1. Overall Security Posture",
            heading_style
        )
    )


    security_score = report["security_score"]


    score_table = Table(
        [
            [
                "Security Score",
                f"{security_score}%"
            ]
        ],
        colWidths=[
            80 * mm,
            80 * mm
        ]
    )


    score_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#e8f0fe")
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                13
            ),

            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                1,
                colors.grey
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                10
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                10
            )

        ])
    )


    story.append(
        score_table
    )


    # ======================================================
    # 2. Asset Summary
    # ======================================================

    story.append(
        Paragraph(
            "2. Asset Summary",
            heading_style
        )
    )


    asset_data = [
        ["Metric", "Value"],

        [
            "Total Assets",
            report["assets"]["total"]
        ],

        [
            "Active Assets",
            report["assets"]["active"]
        ],

        [
            "High / Critical Risk Assets",
            report["assets"]["high_risk"]
        ]
    ]


    asset_table = Table(
        asset_data,
        colWidths=[
            100 * mm,
            60 * mm
        ]
    )


    asset_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e293b")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])
    )


    story.append(
        asset_table
    )


    # ======================================================
    # 3. Vulnerability Scan Summary
    # ======================================================

    story.append(
        Paragraph(
            "3. Vulnerability Scan Summary",
            heading_style
        )
    )


    scan_data = [
        ["Metric", "Value"],

        [
            "Total Scans",
            report["scans"]["total"]
        ],

        [
            "Completed Scans",
            report["scans"]["completed"]
        ],

        [
            "Failed Scans",
            report["scans"]["failed"]
        ]
    ]


    scan_table = Table(
        scan_data,
        colWidths=[
            100 * mm,
            60 * mm
        ]
    )


    scan_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e293b")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])
    )


    story.append(
        scan_table
    )


    # ======================================================
    # 4. Incident Summary
    # ======================================================

    story.append(
        Paragraph(
            "4. Incident Summary",
            heading_style
        )
    )


    incident_data = [
        ["Category", "Count"],

        [
            "Total",
            report["incidents"]["total"]
        ],

        [
            "Open",
            report["incidents"]["open"]
        ],

        [
            "In Progress",
            report["incidents"]["in_progress"]
        ],

        [
            "Resolved",
            report["incidents"]["resolved"]
        ],

        [
            "Closed",
            report["incidents"]["closed"]
        ],

        [
            "Critical",
            report["incidents"]["critical"]
        ],

        [
            "High",
            report["incidents"]["high"]
        ],

        [
            "Medium",
            report["incidents"]["medium"]
        ],

        [
            "Low",
            report["incidents"]["low"]
        ]
    ]


    incident_table = Table(
        incident_data,
        colWidths=[
            100 * mm,
            60 * mm
        ]
    )


    incident_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e293b")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )

        ])
    )


    story.append(
        incident_table
    )


    # ======================================================
    # 5. Recent Incidents
    # ======================================================

    story.append(
        Paragraph(
            "5. Recent Incidents",
            heading_style
        )
    )


    if report["recent_incidents"]:

        incident_history = [
            [
                "Incident ID",
                "Title",
                "Severity",
                "Status"
            ]
        ]


        for incident in report["recent_incidents"]:

            incident_history.append(
                [
                    incident.incident_id or "N/A",

                    Paragraph(
                        escape(
                            str(
                                incident.title or "N/A"
                            )
                        ),
                        small_style
                    ),

                    incident.severity or "N/A",

                    incident.status or "N/A"
                ]
            )


        history_table = Table(
            incident_history,
            colWidths=[
                30 * mm,
                70 * mm,
                30 * mm,
                30 * mm
            ],
            repeatRows=1
        )


        history_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1e293b")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )

            ])
        )


        story.append(
            history_table
        )

    else:

        story.append(
            Paragraph(
                "No incidents recorded.",
                body_style
            )
        )


    # ======================================================
    # 6. Recent Vulnerability Scans
    # ======================================================

    story.append(
        Paragraph(
            "6. Recent Vulnerability Scans",
            heading_style
        )
    )


    if report["recent_scans"]:

        scan_history = [
            [
                "Target",
                "Open Ports",
                "Status",
                "Date"
            ]
        ]


        for scan in report["recent_scans"]:

            scan_date = (
                scan.scan_date.strftime(
                    "%Y-%m-%d %H:%M"
                )
                if scan.scan_date
                else "N/A"
            )


            scan_history.append(
                [
                    scan.target or "N/A",

                    Paragraph(
                        escape(
                            str(
                                scan.open_ports or "None"
                            )
                        ),
                        small_style
                    ),

                    scan.status or "N/A",

                    scan_date
                ]
            )


        scan_history_table = Table(
            scan_history,
            colWidths=[
                35 * mm,
                65 * mm,
                30 * mm,
                30 * mm
            ],
            repeatRows=1
        )


        scan_history_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1e293b")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )

            ])
        )


        story.append(
            scan_history_table
        )

    else:

        story.append(
            Paragraph(
                "No vulnerability scans recorded.",
                body_style
            )
        )


    # ======================================================
    # 7. SOC Correlation Analysis
    # ======================================================

    story.append(
        Paragraph(
            "7. SOC Correlation Analysis",
            heading_style
        )
    )


    correlation = report.get(
        "correlation",
        {}
    )


    if correlation.get("available"):

        # --------------------------------------------------
        # Correlation Summary
        # --------------------------------------------------

        correlation_data = [
            ["Metric", "Value"],

            [
                "Correlated Asset",
                correlation.get(
                    "asset_name",
                    "N/A"
                )
            ],

            [
                "IP Address",
                correlation.get(
                    "ip_address",
                    "N/A"
                )
            ],

            [
                "Asset Risk",
                correlation.get(
                    "asset_risk",
                    "N/A"
                )
            ],

            [
                "Asset Status",
                correlation.get(
                    "asset_status",
                    "N/A"
                )
            ],

            [
                "Related Scans",
                correlation.get(
                    "related_scans",
                    0
                )
            ],

            [
                "Related Incidents",
                correlation.get(
                    "related_incidents",
                    0
                )
            ],

            [
                "Open Ports",
                correlation.get(
                    "open_ports",
                    0
                )
            ],

            [
                "Priority",
                correlation.get(
                    "priority",
                    "N/A"
                )
            ]
        ]


        correlation_table = Table(
            correlation_data,
            colWidths=[
                65 * mm,
                95 * mm
            ]
        )


        correlation_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1e293b")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "FONTNAME",
                    (0, 1),
                    (0, -1),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )

            ])
        )


        story.append(
            correlation_table
        )


        story.append(
            Spacer(1, 8)
        )


        # --------------------------------------------------
        # Correlated Finding
        # --------------------------------------------------

        story.append(
            Paragraph(
                "<b>Correlated Finding</b>",
                body_style
            )
        )


        story.append(
            Paragraph(
                escape(
                    str(
                        correlation.get(
                            "finding",
                            "No correlated finding available."
                        )
                    )
                ),
                body_style
            )
        )


        story.append(
            Spacer(1, 8)
        )


        # --------------------------------------------------
        # Recommended SOC Response
        # --------------------------------------------------

        story.append(
            Paragraph(
                escape(
                    str(
                        correlation.get(
                            "response",
                            "Continue regular security monitoring."
                        )
                    )
                ),
                body_style
            )
        )


        story.append(
            Spacer(1, 8)
        )


        # --------------------------------------------------
        # Correlated Scan Evidence
        # --------------------------------------------------

        correlated_scans = correlation.get(
            "scans",
            []
        )


        if correlated_scans:

            story.append(
                Paragraph(
                    "<b>Correlated Scan Evidence</b>",
                    body_style
                )
            )


            scan_evidence = [
                [
                    "Target",
                    "Open Ports",
                    "Status",
                    "Date"
                ]
            ]


            for scan in correlated_scans:

                scan_date = (
                    scan.scan_date.strftime(
                        "%Y-%m-%d %H:%M"
                    )
                    if scan.scan_date
                    else "N/A"
                )


                scan_evidence.append(
                    [
                        scan.target or "N/A",

                        Paragraph(
                            escape(
                                str(
                                    scan.open_ports or "None"
                                )
                            ),
                            small_style
                        ),

                        scan.status or "N/A",

                        scan_date
                    ]
                )


            scan_evidence_table = Table(
                scan_evidence,
                colWidths=[
                    35 * mm,
                    55 * mm,
                    30 * mm,
                    40 * mm
                ],
                repeatRows=1
            )


            scan_evidence_table.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1e293b")
                    ),

                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),

                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey
                    ),

                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    )

                ])
            )


            story.append(
                scan_evidence_table
            )


            story.append(
                Spacer(1, 8)
            )


        # --------------------------------------------------
        # Correlated Incident Evidence
        # --------------------------------------------------

        correlated_incidents = correlation.get(
            "incidents",
            []
        )


        if correlated_incidents:

            story.append(
                Paragraph(
                    "<b>Correlated Incident Evidence</b>",
                    body_style
                )
            )


            incident_evidence = [
                [
                    "Incident ID",
                    "Title",
                    "Severity",
                    "Status"
                ]
            ]


            for incident in correlated_incidents:

                incident_evidence.append(
                    [
                        incident.incident_id or "N/A",

                        Paragraph(
                            escape(
                                str(
                                    incident.title or "N/A"
                                )
                            ),
                            small_style
                        ),

                        incident.severity or "N/A",

                        incident.status or "N/A"
                    ]
                )


            incident_evidence_table = Table(
                incident_evidence,
                colWidths=[
                    30 * mm,
                    70 * mm,
                    30 * mm,
                    30 * mm
                ],
                repeatRows=1
            )


            incident_evidence_table.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1e293b")
                    ),

                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),

                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey
                    ),

                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP"
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        5
                    )

                ])
            )


            story.append(
                incident_evidence_table
            )


    else:

        story.append(
            Paragraph(
                "No high or critical-risk asset is "
                "currently available for SOC correlation.",
                body_style
            )
        )


    # ======================================================
    # 8. Security Recommendations
    # ======================================================

    story.append(
        Paragraph(
            "8. Security Recommendations",
            heading_style
        )
    )


    recommendations = []


    if report["assets"]["high_risk"] > 0:

        recommendations.append(
            "Review and prioritize high or critical-risk assets."
        )


    if report["incidents"]["critical"] > 0:

        recommendations.append(
            "Immediately investigate critical security incidents."
        )


    if report["incidents"]["open"] > 0:

        recommendations.append(
            "Review and resolve outstanding open incidents."
        )


    if report["scans"]["failed"] > 0:

        recommendations.append(
            "Investigate failed vulnerability scans."
        )


    if not recommendations:

        recommendations.append(
            "Continue regular vulnerability scanning "
            "and security monitoring."
        )


    for recommendation in recommendations:

        story.append(
            Paragraph(
                f"• {escape(str(recommendation))}",
                body_style
            )
        )


        story.append(
            Spacer(1, 4)
        )


    # ======================================================
    # Footer
    # ======================================================

    story.append(
        Spacer(1, 20)
    )


    story.append(
        Paragraph(
            "Enterprise Cyber Defense Platform (ECDP) "
            "— Confidential Security Report",
            subtitle_style
        )
    )


    # ======================================================
    # Build PDF
    # ======================================================

    document.build(
        story
    )


    buffer.seek(0)


    return buffer