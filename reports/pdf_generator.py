"""
reports/pdf_generator.py  —  Forensic PDF Report Generator  (Week 6)
Produces a court-ready digital forensics report using ReportLab.
"""

from __future__ import annotations
import os, datetime
from reportlab.lib             import colors
from reportlab.lib.pagesizes   import A4
from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units       import mm, cm
from reportlab.lib.enums       import TA_CENTER, TA_LEFT
from reportlab.platypus        import (SimpleDocTemplate, Paragraph, Spacer,
                                       Table, TableStyle, HRFlowable, PageBreak)
from engine.logger import get_logger
log = get_logger(__name__)

# ── Palette ───────────────────────────────────────────────────────────────────
C_NAVY    = colors.HexColor("#0f2044")
C_ACCENT  = colors.HexColor("#3b5bdb")
C_LIGHT   = colors.HexColor("#e8eef8")
C_BORDER  = colors.HexColor("#c8d3e8")
C_RED     = colors.HexColor("#c92a2a")
C_ORANGE  = colors.HexColor("#e67700")
C_YELLOW  = colors.HexColor("#927500")
C_GREEN   = colors.HexColor("#1c7c3c")
C_GREY    = colors.HexColor("#6b7280")
C_DARK    = colors.HexColor("#374151")
C_WHITE   = colors.white
C_ROW_ALT = colors.HexColor("#f5f7ff")
SEV_COL   = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN}


def generate_report(report_data: dict, output_dir: str = "reports") -> str:
    """Generate PDF and return its path."""
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"forensic_report_{ts}.pdf")

    meta      = report_data.get("meta",     {})
    stats     = report_data.get("stats",    {})
    flows     = report_data.get("flows",    [])
    beacons   = report_data.get("beacons",  [])
    dns_stats = report_data.get("dns_stats")
    ioc_rep   = report_data.get("ioc_report")
    extracted = report_data.get("extracted_files", [])
    case_info = report_data.get("case_info", {})
    gen_time  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.8*cm, bottomMargin=2.5*cm,
        title="Digital Forensics Analysis Report",
        author=case_info.get("analyst_name", "PCAP Engine"),
    )
    S     = _styles()
    story = []

    story += _cover(S, meta, case_info, gen_time);    story.append(PageBreak())
    story += _toc(S);                                 story.append(PageBreak())
    story += _custody(S, meta, case_info, gen_time);  story.append(Spacer(1,.3*cm))
    story += _exec_summary(S, stats, beacons, dns_stats, ioc_rep, extracted)
    story.append(PageBreak())
    story += _traffic(S, stats);                      story.append(PageBreak())
    story += _sessions(S, flows);                     story.append(PageBreak())
    story += _beacons_sec(S, beacons);                story.append(PageBreak())
    story += _dns_sec(S, dns_stats);                  story.append(PageBreak())
    story += _files_sec(S, extracted);                story.append(PageBreak())
    story += _ioc_sec(S, ioc_rep);                    story.append(PageBreak())
    story += _appendix(S, flows, meta)

    doc.build(story,
              onFirstPage=_header_footer,
              onLaterPages=_header_footer)
    log.info(f"PDF report: {out_path}")
    return out_path


# ── Page chrome ────────────────────────────────────────────────────────────────
def _header_footer(canvas, doc):
    canvas.saveState()
    W, H = A4
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, H-20*mm, W, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE);  canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(2*cm, H-13*mm, "PCAP ENGINE  —  DIGITAL FORENSICS REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(W-2*cm, H-13*mm, datetime.datetime.utcnow().strftime("%Y-%m-%d"))
    canvas.setFillColor(C_GREY);   canvas.setFont("Helvetica", 7.5)
    canvas.drawString(2*cm, 14*mm, "CONFIDENTIAL — For authorised use only")
    canvas.drawCentredString(W/2,  14*mm, f"Page {doc.page}")
    canvas.drawRightString(W-2*cm, 14*mm, "PCAP Engine v1.0")
    canvas.setStrokeColor(C_BORDER); canvas.setLineWidth(.5)
    canvas.line(2*cm, 18*mm, W-2*cm, 18*mm)
    canvas.restoreState()


# ── Sections ───────────────────────────────────────────────────────────────────
def _cover(S, meta, ci, gen_time):
    rows = [
        ["Generated",     gen_time],
        ["Organisation",  ci.get("organisation","N/A")],
        ["Analyst",       ci.get("analyst_name","N/A")],
        ["Case Number",   ci.get("case_number","N/A")],
        ["Evidence File", meta.get("filename","N/A")],
        ["File Size",     _fb(meta.get("file_size",0))],
        ["SHA-256",       (meta.get("sha256") or "N/A")[:48]+"…"],
    ]
    return [
        Spacer(1,2*cm),
        _banner_table("DIGITAL FORENSICS", "ANALYSIS REPORT", S),
        Spacer(1,1.2*cm),
        Paragraph(meta.get("filename","Unknown Capture"), S["cover_title"]),
        Spacer(1,.4*cm),
        Paragraph(f"Case: {ci.get('case_number','N/A')}  ·  "
                  f"Analyst: {ci.get('analyst_name','N/A')}", S["cover_sub"]),
        Spacer(1,1.8*cm),
        _kv(rows, S),
        Spacer(1,1.2*cm),
        HRFlowable(width="100%", thickness=1, color=C_BORDER),
        Spacer(1,.4*cm),
        Paragraph("CONFIDENTIAL — This document contains sensitive forensic findings "
                  "and is intended solely for authorised personnel.", S["disclaimer"]),
    ]


def _toc(S):
    items = [("1","Chain of Custody"),("2","Executive Summary"),
             ("3","Traffic Overview"),("4","Session Analysis"),
             ("5","C2 Beacon Findings"),("6","DNS Analysis"),
             ("7","Extracted Files"),("8","IOC Report"),("9","Evidence Appendix")]
    return [
        Paragraph("Table of Contents", S["h1"]), Spacer(1,.4*cm),
        Table([[f"{n}.", t] for n,t in items], colWidths=[1.2*cm,None],
              style=TableStyle([
                  ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
                  ("FONTSIZE",(0,0),(-1,-1),11),
                  ("TEXTCOLOR",(0,0),(-1,-1),C_DARK),
                  ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
                  ("LINEBELOW",(0,-1),(-1,-1),.5,C_BORDER),
              ])),
    ]


def _custody(S, meta, ci, gen_time):
    rows = [
        ["Evidence Identifier", meta.get("filename","N/A")],
        ["File Path",           meta.get("path","N/A")],
        ["File Size",           _fb(meta.get("file_size",0))],
        ["SHA-256 Hash",        meta.get("sha256","N/A")],
        ["Date of Analysis",    gen_time],
        ["Analysing Tool",      "PCAP Engine v1.0"],
        ["Analyst",             ci.get("analyst_name","N/A")],
        ["Organisation",        ci.get("organisation","N/A")],
        ["Case Reference",      ci.get("case_number","N/A")],
    ]
    return [
        _sec_header("1. Chain of Custody", S),
        Paragraph("The SHA-256 hash below serves as a cryptographic fingerprint "
                  "confirming that the evidence file has not been altered since acquisition.",
                  S["body"]),
        Spacer(1,.4*cm), _kv(rows, S), Spacer(1,.3*cm),
        Paragraph("⚠  Analysis was performed on a verified copy of the evidence. "
                  "The original file was not modified.", S["note"]),
    ]


def _exec_summary(S, stats, beacons, dns_stats, ioc_rep, extracted):
    critical  = sum(1 for b in beacons if b.severity=="CRITICAL")
    high      = sum(1 for b in beacons if b.severity=="HIGH")
    dns_susp  = len(dns_stats.findings) if dns_stats else 0
    mal_files = sum(1 for f in extracted if "MALICIOUS" in f.vt_verdict)
    ioc_count = len(ioc_rep.iocs) if ioc_rep else 0

    if critical or mal_files:
        lvl, col, msg = "CRITICAL", C_RED,    "Critical threats detected. Immediate incident response recommended."
    elif high or dns_susp:
        lvl, col, msg = "HIGH",     C_ORANGE, "High-severity findings. Escalation and investigation required."
    elif ioc_count:
        lvl, col, msg = "MEDIUM",   C_YELLOW, "Suspicious indicators found. Further investigation recommended."
    else:
        lvl, col, msg = "LOW",      C_GREEN,  "No significant threats detected in this capture."

    threat_table = Table(
        [[Paragraph(f"Overall: {lvl}", S["badge"]), Paragraph(msg, S["body"])]],
        colWidths=[4.5*cm, None],
        style=TableStyle([
            ("BACKGROUND",(0,0),(0,0),col),("TEXTCOLOR",(0,0),(0,0),C_WHITE),
            ("ALIGN",(0,0),(0,0),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1),12),("BOTTOMPADDING",(0,0),(-1,-1),12),
            ("LEFTPADDING",(1,0),(1,0),12),("BOX",(0,0),(-1,-1),1,C_BORDER),
        ])
    )

    bullets = []
    tot = stats.get("totals",{})
    if tot:
        bullets.append(f"Capture: <b>{tot.get('packets',0):,} packets</b> / "
                        f"{_fb(tot.get('bytes',0))} / "
                        f"{stats.get('capture',{}).get('duration_human','?')}")
    if beacons:
        bullets.append(f"<b>{len(beacons)}</b> suspicious C2 beacon flow(s) — "
                        f"{critical} CRITICAL, {high} HIGH")
    if dns_stats and dns_stats.findings:
        bullets.append(f"<b>{len(dns_stats.findings)}</b> suspicious DNS domain(s) — "
                        f"{dns_stats.tunnelling_flows} tunnelling, "
                        f"{dns_stats.dga_flows} DGA")
    if extracted:
        bullets.append(f"<b>{len(extracted)}</b> files extracted — "
                        f"{mal_files} confirmed malicious by VirusTotal")
    if ioc_rep:
        bullets.append(f"<b>{ioc_count}</b> IOC(s) across MITRE tactics: "
                        f"{', '.join(ioc_rep.attack_surface) or 'none'}")

    story = [_sec_header("2. Executive Summary", S), threat_table, Spacer(1,.5*cm)]
    for b in bullets:
        story.append(Paragraph(f"• {b}", S["bullet"]))

    if ioc_rep and ioc_rep.attack_surface:
        story.append(Spacer(1,.4*cm))
        story.append(Paragraph("MITRE ATT&CK Coverage", S["h3"]))
        from collections import Counter
        tc = Counter(i.mitre_tactic for i in ioc_rep.iocs if i.mitre_tactic)
        tm = {i.mitre_tactic: i.mitre_technique for i in ioc_rep.iocs if i.mitre_tactic}
        rows = [["Tactic","Technique","IOCs"]] + [
            [t, tm.get(t,""), str(c)] for t,c in tc.most_common()
        ]
        story.append(_dtable(rows, S))
    return story


def _traffic(S, stats):
    cap  = stats.get("capture",{})
    tot  = stats.get("totals",{})
    uniq = stats.get("unique_ips",{})
    kv_rows = [
        ["First Packet",  cap.get("first_packet","N/A")],
        ["Last Packet",   cap.get("last_packet","N/A")],
        ["Duration",      cap.get("duration_human","N/A")],
        ["Total Packets", f"{tot.get('packets',0):,}"],
        ["Total Bytes",   _fb(tot.get("bytes",0))],
        ["Unique IPs",    str(uniq.get("total_unique",0))],
        ["Internal IPs",  str(len(uniq.get("internal",[])))],
        ["External IPs",  str(len(uniq.get("external",[])))],
    ]
    story = [_sec_header("3. Traffic Overview", S), _kv(kv_rows, S), Spacer(1,.5*cm)]

    protos = stats.get("protocols",{})
    if protos:
        story.append(Paragraph("Protocol Breakdown", S["h3"]))
        rows = [["Protocol","Packets","Bytes","Share"]]
        for p,d in protos.items():
            rows.append([p, f"{d['count']:,}", _fb(d['bytes']), f"{d['percent']}%"])
        story.append(_dtable(rows, S))
        story.append(Spacer(1,.4*cm))

    src = stats.get("top_src_ips",[])[:10]
    if src:
        story.append(Paragraph("Top Source IPs", S["h3"]))
        rows = [["IP","Packets","Share"]] + [[e["ip"],f"{e['packets']:,}",f"{e['percent']}%"] for e in src]
        story.append(_dtable(rows, S))

    ports = stats.get("top_dst_ports",[])[:10]
    if ports:
        story.append(Spacer(1,.3*cm))
        story.append(Paragraph("Top Destination Ports", S["h3"]))
        rows = [["Port","Service","Count","Proto"]]
        rows += [[str(p["port"]),p["service"],str(p["count"]),p["protocol"]] for p in ports]
        story.append(_dtable(rows, S))
    return story


def _sessions(S, flows):
    story = [
        _sec_header("4. Session Analysis", S),
        Paragraph(f"{len(flows)} bidirectional flows reconstructed. "
                  "Top 30 by byte volume:", S["body"]),
        Spacer(1,.4*cm),
    ]
    if not flows:
        story.append(Paragraph("No flows.", S["body"])); return story
    rows = [["Source","Destination","Proto","Pkts","Bytes","Dur","Score"]]
    for f in flows[:30]:
        rows.append([
            f"{getattr(f,'src_ip','?')}:{getattr(f,'src_port','?')}",
            f"{getattr(f,'dst_ip','?')}:{getattr(f,'dst_port','?')}",
            getattr(f,"protocol","?"), str(getattr(f,"packet_count",0)),
            _fb(getattr(f,"byte_count",0)),
            f"{getattr(f,'duration_sec',0):.1f}s",
            str(getattr(f,"threat_score",0) or 0),
        ])
    story.append(_dtable(rows, S, fs=8))
    if len(flows)>30:
        story.append(Paragraph(f"… {len(flows)-30} more flows in Appendix.", S["note"]))
    return story


def _beacons_sec(S, beacons):
    story = [_sec_header("5. C2 Beacon Findings", S)]
    if not beacons:
        story.append(Paragraph("No C2 beaconing patterns detected.", S["body"]))
        return story
    story.append(Paragraph(f"{len(beacons)} suspicious flow(s) with beaconing characteristics.", S["body"]))
    story.append(Spacer(1,.4*cm))
    for b in beacons:
        col = SEV_COL.get(b.severity, C_GREY)
        hdr = Table([[
            Paragraph(b.severity,  S["badge"]),
            Paragraph(f"{b.src_ip} → {b.dst_ip}:{b.dst_port or '?'} [{b.protocol}]", S["mono"]),
            Paragraph(f"Score: {b.threat_score}/100", S["body"]),
        ]], colWidths=[2*cm,None,3*cm], style=TableStyle([
            ("BACKGROUND",(0,0),(0,0),col),("TEXTCOLOR",(0,0),(0,0),C_WHITE),
            ("ALIGN",(0,0),(0,0),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LEFTPADDING",(1,0),(1,0),10),("BOX",(0,0),(-1,-1),.5,C_BORDER),
            ("BACKGROUND",(1,0),(-1,0),colors.HexColor("#f8faff")),
        ]))
        story.append(hdr)
        kv = [["Interval mean", f"{b.interval_mean:.2f}s"],
              ["Interval CV",   f"{b.interval_cv:.4f}"],
              ["Packets",       str(b.packet_count)]]
        if b.ja3_hash:  kv.append(["JA3 hash",    b.ja3_hash])
        if b.ja3_match: kv.append(["JA3 malware", b.ja3_match])
        story.append(_kv(kv, S))
        for r in b.reasons:
            story.append(Paragraph(f"  → {r}", S["reason"]))
        story.append(Spacer(1,.4*cm))
    return story


def _dns_sec(S, dns_stats):
    story = [_sec_header("6. DNS Analysis", S)]
    if not dns_stats or not dns_stats.findings:
        story.append(Paragraph("No suspicious DNS activity detected.", S["body"]))
        return story
    story.append(Paragraph(
        f"{len(dns_stats.findings)} suspicious domain(s) — "
        f"{dns_stats.tunnelling_flows} tunnelling, {dns_stats.dga_flows} DGA.",
        S["body"]
    ))
    story.append(Spacer(1,.4*cm))
    rows = [["Sev","Score","Domain","Queries","Entropy","Tunnel","DGA"]]
    for f in dns_stats.findings:
        rows.append([f.severity, str(f.threat_score), f.domain, str(f.query_count),
                     f"{f.entropy:.2f}", "YES" if f.is_tunnelling else "—",
                     "YES" if f.is_dga else "—"])
    story.append(_dtable(rows, S))
    story.append(Spacer(1,.4*cm))
    for f in dns_stats.findings[:5]:
        story.append(Paragraph(f"Domain: {f.domain}", S["h3"]))
        for r in f.reasons:
            story.append(Paragraph(f"  → {r}", S["reason"]))
        story.append(Spacer(1,.15*cm))
    return story


def _files_sec(S, extracted):
    story = [_sec_header("7. Extracted Files", S)]
    if not extracted:
        story.append(Paragraph("No files extracted.", S["body"])); return story
    story.append(Paragraph(f"{len(extracted)} file(s) recovered from network streams.", S["body"]))
    story.append(Spacer(1,.4*cm))
    rows = [["Filename","Size","Type","Method","VT Verdict","SHA-256 (partial)"]]
    for ef in extracted:
        rows.append([ef.filename[:28], _fb(ef.size_bytes),
                     (ef.file_type or "")[:22], ef.extract_method,
                     ef.vt_verdict, ef.sha256[:20]+"…"])
    story.append(_dtable(rows, S, fs=8))
    mal = [ef for ef in extracted if "MALICIOUS" in ef.vt_verdict]
    if mal:
        story.append(Spacer(1,.3*cm))
        story.append(Paragraph("⚠  Malicious Files", S["warn"]))
        for ef in mal:
            story.append(Paragraph(f"File: {ef.filename}", S["body"]))
            story.append(Paragraph(f"SHA-256: {ef.sha256}", S["mono"]))
            story.append(Paragraph(f"VT: {ef.vt_malicious}/{ef.vt_total} engines  |  Source: {ef.source_flow}", S["body"]))
    return story


def _ioc_sec(S, ioc_rep):
    story = [_sec_header("8. IOC Report", S)]
    if not ioc_rep or not ioc_rep.iocs:
        story.append(Paragraph("No IOCs identified.", S["body"])); return story
    story.append(Paragraph(
        f"{len(ioc_rep.iocs)} IOC(s)  |  "
        f"CRITICAL:{ioc_rep.critical_count}  HIGH:{ioc_rep.high_count}  "
        f"MEDIUM:{ioc_rep.medium_count}", S["body"]
    ))
    story.append(Spacer(1,.4*cm))
    rows = [["Sev","Score","Type","Value","Tactic","Technique"]]
    for i in ioc_rep.iocs:
        v = i.value
        rows.append([i.severity[:4], str(i.threat_score), i.ioc_type,
                     (v[:38]+"…") if len(v)>40 else v,
                     (i.mitre_tactic or "—")[:18], i.mitre_technique or "—"])
    story.append(_dtable(rows, S, fs=8))
    return story


def _appendix(S, flows, meta):
    story = [
        _sec_header("9. Evidence Appendix", S),
        Paragraph("Complete flow list:", S["body"]), Spacer(1,.3*cm),
    ]
    rows = [["#","Src IP","Src Port","Dst IP","Dst Port","Proto","Pkts","Bytes"]]
    for i,f in enumerate(flows,1):
        rows.append([str(i), getattr(f,"src_ip","?"), str(getattr(f,"src_port","?")),
                     getattr(f,"dst_ip","?"), str(getattr(f,"dst_port","?")),
                     getattr(f,"protocol","?"), str(getattr(f,"packet_count",0)),
                     _fb(getattr(f,"byte_count",0))])
    story.append(_dtable(rows, S, fs=7.5))
    story.append(Spacer(1,.5*cm))
    story.append(Paragraph(f"Evidence SHA-256: {meta.get('sha256','N/A')}", S["mono"]))
    story.append(Paragraph("— End of Report —", S["center"]))
    return story


# ── Helpers ────────────────────────────────────────────────────────────────────
def _banner_table(left, right, S):
    return Table([[Paragraph(left,S["banner"]), Paragraph(right,S["banner_r"])]],
        colWidths=["50%","50%"],
        style=TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),C_NAVY),
            ("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14),
            ("LEFTPADDING",(0,0),(0,0),16),("RIGHTPADDING",(1,0),(1,0),16),
        ]))


def _sec_header(title, S):
    return Table([[Paragraph(title, S["h1"])]],
        style=TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),C_LIGHT),
            ("LINEBELOW",(0,0),(-1,-1),2,C_ACCENT),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LEFTPADDING",(0,0),(-1,-1),8),
        ]))


def _kv(rows, S):
    return Table(rows, colWidths=[4.5*cm,None], style=TableStyle([
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8.5),
        ("TEXTCOLOR",(0,0),(0,-1),C_DARK),("TEXTCOLOR",(1,0),(1,-1),colors.black),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LINEBELOW",(0,0),(-1,-2),.3,C_BORDER),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white,C_ROW_ALT]),
    ]))


def _dtable(rows, S, fs=9):
    return Table(rows, repeatRows=1, style=TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),fs),
        ("TOPPADDING",(0,0),(-1,0),6),("BOTTOMPADDING",(0,0),(-1,0),6),
        ("FONTSIZE",(0,1),(-1,-1),fs),("FONTNAME",(0,1),(-1,-1),"Helvetica"),
        ("TEXTCOLOR",(0,1),(-1,-1),C_DARK),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_ROW_ALT]),
        ("TOPPADDING",(0,1),(-1,-1),4),("BOTTOMPADDING",(0,1),(-1,-1),4),
        ("LINEBELOW",(0,0),(-1,-1),.3,C_BORDER),("BOX",(0,0),(-1,-1),.5,C_BORDER),
    ]))


def _styles():
    base = getSampleStyleSheet()
    def ps(name,**kw):
        return ParagraphStyle(name,parent=base["Normal"],**kw)
    return {
        "body":       ps("body",       fontSize=9.5, leading=14, textColor=C_DARK),
        "bullet":     ps("bullet",     fontSize=9.5, leading=14, leftIndent=12, textColor=C_DARK),
        "note":       ps("note",       fontSize=8.5, leading=12, textColor=C_GREY,
                          backColor=colors.HexColor("#f0f4ff"),
                          borderPad=5, borderColor=C_ACCENT, borderWidth=0.5),
        "warn":       ps("warn",       fontSize=10,  fontName="Helvetica-Bold", textColor=C_RED),
        "mono":       ps("mono",       fontName="Courier", fontSize=8, leading=12, textColor=C_DARK),
        "reason":     ps("reason",     fontSize=8.5, leading=13, leftIndent=16, textColor=C_DARK),
        "disclaimer": ps("disclaimer", fontSize=8,   leading=12, textColor=C_GREY, alignment=TA_CENTER),
        "cover_title":ps("ct",         fontName="Helvetica-Bold", fontSize=20, leading=26, textColor=C_NAVY),
        "cover_sub":  ps("cs",         fontSize=11, textColor=C_GREY),
        "h1":         ps("h1",         fontName="Helvetica-Bold", fontSize=14, leading=20,
                          textColor=C_NAVY, spaceBefore=6, spaceAfter=4),
        "h3":         ps("h3",         fontName="Helvetica-Bold", fontSize=10.5, leading=16,
                          textColor=C_DARK, spaceBefore=4),
        "badge":      ps("badge",      fontName="Helvetica-Bold", fontSize=9,
                          textColor=C_WHITE, alignment=TA_CENTER),
        "center":     ps("center",     fontSize=9,   alignment=TA_CENTER, textColor=C_GREY),
        "banner":     ps("banner",     fontName="Helvetica-Bold", fontSize=11,
                          textColor=C_WHITE, alignment=TA_LEFT),
        "banner_r":   ps("banner_r",   fontName="Helvetica-Bold", fontSize=11,
                          textColor=C_WHITE, alignment=4),  # TA_RIGHT=4
    }


def _fb(b):
    b = int(b or 0)
    for u in ("B","KB","MB","GB"):
        if b < 1024: return f"{b:.1f} {u}"
        b //= 1024
    return f"{b:.1f} TB"
