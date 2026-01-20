"""HTML report generator with beautiful styling."""

from pathlib import Path
from datetime import datetime
from typing import Optional

from jinja2 import Template

from ..core.models import ScanResult, Severity


class HtmlReporter:
    """Reporter that generates beautiful HTML reports."""
    
    TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supply Chain Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 2rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            backdrop-filter: blur(10px);
        }
        
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        
        .timestamp {
            color: #888;
            font-size: 0.9rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s, box-shadow 0.2s;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            opacity: 0.7;
        }
        
        .summary-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
        }
        
        .summary-card .number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .summary-card .label {
            color: #888;
            font-size: 0.9rem;
        }
        
        .green { color: #00ff88; }
        .yellow { color: #ffd700; }
        .red { color: #ff4757; }
        
        section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        section:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
        }
        
        h2 {
            font-size: 1.4rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            border-radius: 8px;
            overflow: hidden;
        }
        
        th, td {
            padding: 0.85rem 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }
        
        th {
            background: rgba(255, 255, 255, 0.08);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            color: #aaa;
        }
        
        tbody tr {
            transition: background 0.15s;
        }
        
        tbody tr:hover {
            background: rgba(255, 255, 255, 0.04);
        }
        
        tbody tr:last-child td {
            border-bottom: none;
        }
        
        .severity-critical {
            background: linear-gradient(90deg, #ff4757, #ff6b7a);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .severity-high {
            background: linear-gradient(90deg, #ff6348, #ff7f50);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .severity-medium {
            background: linear-gradient(90deg, #ffa502, #ffcc00);
            color: #1a1a2e;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .severity-low {
            background: linear-gradient(90deg, #3498db, #5dade2);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .risk-high {
            color: #ff4757;
            font-weight: bold;
        }
        
        .risk-medium {
            color: #ffa502;
        }
        
        .risk-low {
            color: #00ff88;
        }
        
        /* Fix Indicator Styles */
        .fix-available {
            color: #00ff88;
            font-weight: 500;
        }
        
        .fix-pending {
            color: #ffa502;
            font-weight: 500;
        }
        
        .fix-none {
            color: #888;
        }
        
        /* Summary Cell with Expandable */
        .summary-cell {
            max-width: 350px;
            line-height: 1.4;
        }
        
        .summary-short {
            color: #ccc;
            font-size: 0.9rem;
        }
        
        .summary-expand {
            color: #00d4ff;
            font-size: 0.75rem;
            cursor: pointer;
            margin-left: 0.5rem;
            opacity: 0.8;
            transition: opacity 0.2s;
        }
        
        .summary-expand:hover {
            opacity: 1;
            text-decoration: underline;
        }
        
        .summary-full {
            display: none;
            margin-top: 0.5rem;
            padding: 0.75rem;
            background: rgba(0, 212, 255, 0.08);
            border-left: 3px solid #00d4ff;
            border-radius: 4px;
            font-size: 0.85rem;
            color: #e0e0e0;
            line-height: 1.5;
        }
        
        .summary-cell.expanded .summary-full {
            display: block;
        }
        
        .summary-cell.expanded .summary-expand {
            color: #ffa502;
        }
        
        /* PMI Maturity Levels */
        .maturity-mature {
            color: #00ff88;
            font-weight: bold;
        }
        
        .maturity-established {
            color: #00ff88;
        }
        
        .maturity-emerging {
            color: #ffa502;
        }
        
        .maturity-early-stage {
            color: #ff4757;
        }
        
        .score-bar {
            height: 8px;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.1);
            overflow: hidden;
        }
        
        .score-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .score-high { background: linear-gradient(90deg, #00ff88, #00d4aa); }
        .score-medium { background: linear-gradient(90deg, #ffa502, #ffcc00); }
        .score-low-bar { background: linear-gradient(90deg, #ff4757, #ff6b7a); }
        
        .status-pass {
            background: linear-gradient(90deg, #00ff88, #00d4aa);
            color: #1a1a2e;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        
        .status-fail {
            background: linear-gradient(90deg, #ff4757, #ff6b7a);
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        
        footer {
            text-align: center;
            color: #666;
            font-size: 0.8rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        /* Executive Summary */
        .executive-summary {
            background: linear-gradient(135deg, rgba(30, 30, 50, 0.9), rgba(20, 20, 40, 0.95));
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 2px solid rgba(255, 255, 255, 0.1);
        }
        
        .posture-critical {
            border-color: #ff4757;
            box-shadow: 0 0 30px rgba(255, 71, 87, 0.3);
        }
        
        .posture-high {
            border-color: #ff6b35;
            box-shadow: 0 0 30px rgba(255, 107, 53, 0.3);
        }
        
        .posture-moderate {
            border-color: #ffa502;
            box-shadow: 0 0 30px rgba(255, 165, 2, 0.3);
        }
        
        .posture-low {
            border-color: #00ff88;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
        }
        
        .posture-badge {
            display: inline-block;
            padding: 0.5rem 1.5rem;
            border-radius: 30px;
            font-size: 1.2rem;
            font-weight: bold;
            margin-bottom: 1rem;
        }
        
        .badge-critical { background: linear-gradient(90deg, #ff4757, #ff6b7a); color: white; }
        .badge-high { background: linear-gradient(90deg, #ff6b35, #ff8c5a); color: white; }
        .badge-moderate { background: linear-gradient(90deg, #ffa502, #ffbc33); color: #1a1a2e; }
        .badge-low { background: linear-gradient(90deg, #00ff88, #33ffaa); color: #1a1a2e; }
        
        .exec-title {
            font-size: 1.6rem;
            margin-bottom: 1rem;
            color: #fff;
        }
        
        .exec-findings {
            list-style: none;
            padding: 0;
            margin: 1rem 0;
        }
        
        .exec-findings li {
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .exec-findings li:last-child {
            border-bottom: none;
        }
        
        .exec-callout {
            background: rgba(255,255,255,0.05);
            border-left: 4px solid #ffa502;
            padding: 1rem;
            margin-top: 1rem;
            font-style: italic;
            color: #aaa;
        }
        
        /* Actionability */
        .fix-available {
            background: #00ff88;
            color: #1a1a2e;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        
        .fix-none {
            background: #666;
            color: #fff;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
        }
        
        .action-text {
            color: #ffa502;
            font-size: 0.85rem;
        }
        
        /* Print-friendly styles */
        @media print {
            body {
                background: white !important;
                color: black !important;
                padding: 0;
                font-size: 11pt;
            }
            
            .container {
                max-width: 100%;
            }
            
            header, section, .executive-summary, .summary-grid {
                background: white !important;
                border: 1px solid #ccc !important;
                box-shadow: none !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            h1 {
                background: none !important;
                -webkit-text-fill-color: black !important;
                color: black !important;
            }
            
            h2, h3 {
                color: black !important;
            }
            
            table {
                border: 1px solid #ccc;
            }
            
            th {
                background: #f0f0f0 !important;
                color: black !important;
            }
            
            td, th {
                border: 1px solid #ddd !important;
                color: black !important;
            }
            
            .summary-card {
                border: 1px solid #ccc !important;
                background: #f9f9f9 !important;
            }
            
            .number {
                color: black !important;
            }
            
            .severity-critical, .severity-high {
                background: #ff4757 !important;
                color: white !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            .severity-medium {
                background: #ffa502 !important;
                color: black !important;
            }
            
            .severity-low {
                background: #00ff88 !important;
                color: black !important;
            }
            
            .posture-badge {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            .status-pass, .status-fail {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            
            /* Page breaks */
            section {
                page-break-inside: avoid;
            }
            
            tr {
                page-break-inside: avoid;
            }
            
            footer {
                position: fixed;
                bottom: 0;
                color: #666 !important;
            }
        }
        
        /* Tooltips */
        .tooltip {
            position: relative;
            display: inline-block;
            cursor: help;
        }
        
        .tooltip .info-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
            color: #888;
            font-size: 10px;
            margin-left: 4px;
            vertical-align: middle;
        }
        
        .tooltip .info-icon:hover {
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
        }
        
        .tooltip .tooltip-text {
            visibility: hidden;
            width: 280px;
            background: #1a1a2e;
            color: #e0e0e0;
            text-align: left;
            border-radius: 8px;
            padding: 12px;
            position: absolute;
            z-index: 1000;
            bottom: 125%;
            left: 50%;
            margin-left: -140px;
            opacity: 0;
            transition: opacity 0.3s, visibility 0.3s;
            font-size: 0.85rem;
            line-height: 1.4;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .tooltip .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #1a1a2e transparent transparent transparent;
        }
        
        .tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
        
        @media print {
            .tooltip .tooltip-text {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Supply Chain Security Report</h1>
            <p class="timestamp">Generated: {{ scan_time }}</p>
            <p class="timestamp">Project: {{ project_path }}</p>
        </header>
        
        <!-- Executive Summary -->
        <div class="executive-summary posture-{{ security_posture|default('low') }}">
            <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem;">
                <span class="posture-badge badge-{{ security_posture|default('low') }}">
                    Runtime Risk: {{ security_posture|default('LOW')|upper }}
                </span>
                {% if critical_actual_count > 0 or high_count > 0 %}
                <span class="posture-badge badge-critical" style="background: linear-gradient(90deg, #ff4757, #c0392b);">
                    ❌ Deployment: BLOCKED
                </span>
                {% else %}
                <span class="posture-badge badge-low" style="background: linear-gradient(90deg, #00ff88, #00d4aa);">
                    ✅ Deployment: READY
                </span>
                {% endif %}
            </div>
            <h3 class="exec-title">📋 Executive Summary</h3>
            <ul class="exec-findings">
                {% if high_count > 0 %}
                <li>🔴 <strong>{{ high_count }}</strong> HIGH-severity vulnerabilities detected</li>
                {% endif %}
                {% if critical_actual_count > 0 %}
                <li>🔴 <strong>{{ critical_actual_count }}</strong> CRITICAL-severity vulnerabilities detected</li>
                {% endif %}
                {% if unknown_count > 0 %}
                <li>⚠️ <strong>{{ unknown_count }}</strong> vulnerabilities with unknown severity (treated conservatively)</li>
                {% endif %}
                {% if total_vulnerabilities > 0 %}
                <li>📊 <strong>{{ total_vulnerabilities }}</strong> total vulnerabilities in <strong>{{ affected_packages|default(1) }}</strong> package(s)</li>
                {% endif %}
                {% if max_ses_package %}
                <li>🎯 Highest risk: <code>{{ max_ses_package }}</code> (SES: {{ max_ses_score }}/10)</li>
                {% endif %}
                {% if has_fix_available %}
                <li>✅ <strong>Fix available</strong> - upgrade required</li>
                {% endif %}
                {% if total_vulnerabilities == 0 %}
                <li>✅ No known vulnerabilities detected</li>
                {% endif %}
            </ul>
            
            <!-- Posture Explanation -->
            {% if total_vulnerabilities > 0 %}
            <div style="margin-top: 0.75rem; padding: 0.75rem; background: rgba(255,255,255,0.03); border-radius: 4px; font-size: 0.9rem; color: #aaa;">
                📌 <strong>Why {{ security_posture|upper }}?</strong>
                {% if security_posture == 'critical' %}
                Max SES score is {{ max_ses_score }}/10 (≥8.0 threshold). Immediate action required.
                {% elif security_posture == 'high' %}
                Max SES score is {{ max_ses_score }}/10 (≥6.0 threshold). Prioritize remediation.
                {% elif security_posture == 'moderate' %}
                Max SES score is {{ max_ses_score }}/10 (below HIGH threshold of 6.0). Internal exposure only, no confirmed exploit paths.
                {% else %}
                No significant vulnerabilities detected.
                {% endif %}
            </div>
            {% endif %}
            
            <!-- Recommended Actions -->
            {% if total_vulnerabilities > 0 %}
            <div style="margin-top: 0.75rem; padding: 1rem; background: rgba(255,255,255,0.05); border-left: 3px solid #ffa502; border-radius: 4px;">
                <strong>Recommended actions:</strong>
                {% if has_fix_available %}
                Upgrade affected packages to patched versions.
                {% else %}
                Mitigation or upgrade recommended where applicable before production deployment.
                {% endif %}
                {% if max_ses_package and 'jinja' in max_ses_package|lower %}
                Review template usage for untrusted input. Apply sandbox hardening where possible.
                {% endif %}
            </div>
            {% endif %}
            
            <!-- Scan Confidence -->
            <div style="margin-top: 0.75rem; font-size: 0.85rem; color: #888;">
                🔍 <strong>Scan Confidence:</strong> {{ scan_confidence }}
                ({{ total_dependencies }} dependencies analyzed{% if has_lock_file %}, lock file present{% endif %})
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number green">{{ total_dependencies }}</div>
                <div class="label">Dependencies Scanned</div>
            </div>
            <div class="summary-card">
                <div class="number {{ 'red' if total_vulnerabilities > 0 else 'green' }}">{{ total_vulnerabilities }}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="number {{ 'yellow' if typosquat_count > 0 else 'green' }}">{{ typosquat_count }}</div>
                <div class="label">Typosquatting Alerts</div>
            </div>
            <div class="summary-card">
                <div class="number {{ 'yellow' if license_issues > 0 else 'green' }}">{{ license_issues }}</div>
                <div class="label">License Issues</div>
            </div>
        </div>
        
        {% if vulnerabilities %}
        <section>
            <h2>🔓 Vulnerabilities
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>Known security vulnerabilities</strong> found in your dependencies via the OSV database. 
                        CRITICAL/HIGH severity should be patched immediately.
                    </span>
                </span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>CVE ID</th>
                        <th>Severity
                            <span class="tooltip">
                                <span class="info-icon">ⓘ</span>
                                <span class="tooltip-text">
                                    <strong>CVSS Severity:</strong><br>
                                    • CRITICAL (9.0-10.0): Immediate action required<br>
                                    • HIGH (7.0-8.9): Patch urgently<br>
                                    • MEDIUM (4.0-6.9): Plan remediation<br>
                                    • LOW (0.0-3.9): Monitor
                                </span>
                            </span>
                        </th>
                        <th>Summary</th>
                        <th>Fix</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dep_id, vulns in vulnerabilities.items() %}
                    {% for vuln in vulns %}
                    <tr>
                        <td>{{ dep_id.split(':')[1] if ':' in dep_id else dep_id }}</td>
                        <td>{{ vuln.id }}</td>
                        <td><span class="severity-{{ vuln.severity.value }}">{{ vuln.severity.value|upper }}</span></td>
                        <td class="summary-cell" onclick="this.classList.toggle('expanded')">
                            <span class="summary-short">
                                {{ vuln.summary[:60] }}{% if vuln.summary|length > 60 %}…
                                <span class="summary-expand">▼ more</span>
                                {% endif %}
                            </span>
                            {% if vuln.summary|length > 60 %}
                            <div class="summary-full">{{ vuln.summary }}</div>
                            {% endif %}
                        </td>
                        <td>
                            {% set clean_fix = namespace(value=none) %}
                            {% for fix in vuln.fixed_versions or [] %}
                                {% if fix and fix|length < 20 %}
                                    {% set clean_fix.value = fix %}
                                {% endif %}
                            {% endfor %}
                            {% if clean_fix.value %}
                            <span class="fix-available">✓ {{ clean_fix.value }}</span>
                            {% elif vuln.fixed_versions %}
                            <span class="fix-pending">🔧 Fix pending</span>
                            {% else %}
                            <span class="fix-none">No fix</span>
                            {% endif %}
                        </td>
                        <td class="action-text">
                            {% if clean_fix.value %}
                            Upgrade to ≥{{ clean_fix.value }}
                            {% elif vuln.fixed_versions %}
                            Monitor for release
                            {% else %}
                            Monitor / Mitigate
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}
        
        {% if ses_scores %}
        <section>
            <h2>🔒 Security Exposure Assessment
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>SES measures vulnerability risk</strong>, NOT project quality.<br><br>
                        Formula: Severity + Exploitability + Exposure - Mitigations<br><br>
                        A mature package (high PMI) can still have high SES if it has unpatched vulnerabilities.
                    </span>
                </span>
            </h2>
            <p style="color: #888; margin-bottom: 1rem;">Security Exposure Score (SES) measures actual vulnerability risk, independent of project maturity.</p>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>SES</th>
                        <th>Exposure</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {% for pkg, score in ses_scores.items() %}
                    <tr>
                        <td>{{ pkg.split(':')[1] if ':' in pkg else pkg }}</td>
                        <td>
                            <span class="severity-{{ 'critical' if score.ses_score >= 8 else ('high' if score.ses_score >= 6 else ('medium' if score.ses_score >= 4 else 'low')) }}">
                                {{ "%.1f"|format(score.ses_score) }}/10 ({{ score.ses_level|upper }})
                            </span>
                        </td>
                        <td>
                            {% if score.components.get('exposure', 5) >= 7 %}
                            <span style="color: #ff6b6b;">Public-facing</span>
                            <div style="font-size: 0.75rem; color: #888;">External network, untrusted input</div>
                            {% elif score.components.get('exposure', 5) >= 4 %}
                            <span style="color: #ffa502;">Internal</span>
                            <div style="font-size: 0.75rem; color: #888;">Backend service, no direct untrusted input</div>
                            {% else %}
                            <span style="color: #00d4aa;">Limited</span>
                            <div style="font-size: 0.75rem; color: #888;">Dev/testing context, isolated</div>
                            {% endif %}
                        </td>
                        <td style="font-size: 0.85rem; color: #aaa;">
                            {% if score.ses_score >= 6 %}
                            Remote exploitable + no patch applied
                            {% elif score.ses_score >= 4 %}
                            Known vulnerability requires attention
                            {% else %}
                            Low exposure risk
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p style="margin-top: 1rem; padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 8px; font-size: 0.9rem;">
                <strong>Note:</strong> High PMI (project maturity) does not mean low SES (security exposure). 
                A mature, popular package can still have critical vulnerabilities.
            </p>
        </section>
        {% endif %}
        
        {% if typosquats %}
        <section>
            <h2>🎭 Typosquatting Alerts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Suspicious Package</th>
                        <th>Similar To</th>
                        <th>Similarity</th>
                        <th>Detection Method</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
                    {% for match in typosquats %}
                    <tr>
                        <td>{{ match.suspicious_package }}</td>
                        <td>{{ match.legitimate_package }}</td>
                        <td>{{ "%.1f"|format(match.similarity_score * 100) }}%</td>
                        <td>{{ match.detection_method }}</td>
                        <td class="risk-{{ match.risk_level }}">{{ match.risk_level|upper }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}
        
        {% if license_list %}
        <section>
            <h2>📜 License Issues</h2>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>License</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dep, license_info in license_list %}
                    <tr>
                        <td>{{ dep.name }}@{{ dep.version }}</td>
                        <td>{{ license_info.spdx_id }}</td>
                        <td>{{ 'Copyleft' if license_info.is_copyleft else 'Non-Permissive' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}
        
        {% if reputation_scores %}
        <section>
            <h2>📊 Project Maturity Index (PMI)
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>PMI measures project health</strong>, NOT security.<br><br>
                        Factors: Age (30%), Documentation (20%), Activity (30%), Adoption (20%)<br><br>
                        ⚠️ A MATURE package can still have critical vulnerabilities!
                    </span>
                </span>
            </h2>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Score</th>
                        <th>Maturity</th>
                        <th>Factors</th>
                    </tr>
                </thead>
                <tbody>
                    {% for name, score in reputation_scores.items() %}
                    <tr>
                        <td>{{ name }}</td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <span>{{ "%.0f"|format(score.overall_score) }}/100</span>
                                <div class="score-bar" style="width: 60px;">
                                    <div class="score-fill {{ 'score-high' if score.overall_score >= 80 else ('score-medium' if score.overall_score >= 40 else 'score-low-bar') }}" style="width: {{ score.overall_score }}%;"></div>
                                </div>
                            </div>
                        </td>
                        <td class="maturity-{{ score.maturity_level|default('emerging') }}">{{ (score.maturity_level|default('emerging'))|upper }}</td>
                        <td style="font-size: 0.85rem; color: #888;">Age: {{ "%.0f"|format(score.factors.get('age', 0)) }}, Docs: {{ "%.0f"|format(score.factors.get('documentation', 0)) }}, Activity: {{ "%.0f"|format(score.factors.get('activity', 0)) }}, Adoption: {{ "%.0f"|format(score.factors.get('adoption', 0)) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
        {% endif %}
        
        <section>
            <h2>🎯 Security-Relevant Dependencies
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>Higher attack surface.</strong> These packages handle network, parsing, crypto, or database operations - prioritize their security.
                    </span>
                </span>
            </h2>
            {% if security_relevant_deps %}
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Risk Category</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dep, classification in security_relevant_deps %}
                    <tr>
                        <td>{{ dep.name }}</td>
                        <td>{{ dep.version }}</td>
                        <td>{{ 'Direct' if dep.is_direct else 'Transitive' }}</td>
                        <td><span style="color: #ff6b7a;">🔴 {{ classification.reason }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: #888;">No security-relevant dependencies found.</p>
            {% endif %}
        </section>
        
        <section>
            <h2>⚠️ Conditionally Relevant
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>Risk depends on usage.</strong> Template engines, markup libraries, and WSGI utilities are only risky if exposed to untrusted input.
                    </span>
                </span>
            </h2>
            {% if conditionally_relevant_deps %}
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Context</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dep, classification in conditionally_relevant_deps %}
                    <tr>
                        <td>{{ dep.name }}</td>
                        <td>{{ dep.version }}</td>
                        <td>{{ 'Direct' if dep.is_direct else 'Transitive' }}</td>
                        <td><span style="color: #ffa502;">🟡 {{ classification.reason }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: #888;">No conditionally-relevant dependencies found.</p>
            {% endif %}
        </section>
        
        <section>
            <h2>📦 Support Libraries
                <span class="tooltip">
                    <span class="info-icon">ⓘ</span>
                    <span class="tooltip-text">
                        <strong>Lower attack surface.</strong> These packages handle typing, docs, testing, or utilities - not network/crypto/parsing.
                    </span>
                </span>
            </h2>
            {% if support_deps %}
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Category</th>
                    </tr>
                </thead>
                <tbody>
                    {% for dep, classification in support_deps %}
                    <tr>
                        <td>{{ dep.name }}</td>
                        <td>{{ dep.version }}</td>
                        <td>{{ 'Direct' if dep.is_direct else 'Transitive' }}</td>
                        <td><span style="color: #888;">{{ classification.reason }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p style="color: #888;">No support libraries found.</p>
            {% endif %}
        </section>
        
        <div class="{{ 'status-pass' if not has_issues else 'status-fail' }}">
            {% if has_issues %}
            🚨 <strong>Action Required</strong><br>
            {% if critical_count > 0 %}
            {{ critical_count }} HIGH/CRITICAL-severity vulnerabilities detected in runtime dependencies.<br>
            {% endif %}
            {% if total_vulnerabilities > 0 %}
            Upgrade recommended before production deployment.
            {% endif %}
            {% else %}
            ✅ No security issues found! All dependencies pass security checks.
            {% endif %}
        </div>
        
        <footer>
            <p>Generated by Supply Chain Security Analyzer v0.1.0</p>
        </footer>
    </div>
</body>
</html>'''
    
    def report(self, result: ScanResult, output_path: Optional[Path] = None) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            result: The scan results
            output_path: Optional file path to write the report to
            
        Returns:
            HTML string of the report
        """
        template = Template(self.TEMPLATE)
        
        # Calculate executive summary data - separate counts by actual severity
        critical_actual_count = 0  # Only CRITICAL severity
        high_count = 0             # Only HIGH severity
        unknown_count = 0          # UNKNOWN severity (tracked separately)
        has_fix_available = False
        for vulns in result.vulnerabilities.values():
            for v in vulns:
                if v.severity == Severity.CRITICAL:
                    critical_actual_count += 1
                elif v.severity == Severity.HIGH:
                    high_count += 1
                elif v.severity == Severity.UNKNOWN:
                    unknown_count += 1
                if getattr(v, 'fixed_versions', None):
                    has_fix_available = True
        
        # Combined count for posture (excludes UNKNOWN from critical assessment)
        critical_count = critical_actual_count + high_count
        
        # Get SES data FIRST (needed for posture calculation)
        max_ses_package = None
        max_ses_score = 0
        if hasattr(result, 'ses_scores') and result.ses_scores:
            for pkg, score in result.ses_scores.items():
                if score.ses_score > max_ses_score:
                    max_ses_score = score.ses_score
                    max_ses_package = pkg
        
        # Determine security posture based on SES, not just vulnerability count (issue #1)
        # CRITICAL posture requires SES >= 8 or active exploitation
        if max_ses_score >= 8:
            security_posture = "critical"
        elif max_ses_score >= 6:
            security_posture = "high"
        elif max_ses_score >= 4 or result.total_vulnerabilities > 0:
            security_posture = "moderate"
        else:
            security_posture = "low"
        
        affected_packages = len(result.vulnerabilities)
        
        # Calculate scan confidence
        from pathlib import Path
        project_path = Path(result.project_path)
        has_lock_file = (
            (project_path / "Pipfile.lock").exists() or
            (project_path / "poetry.lock").exists() or
            (project_path / "uv.lock").exists() or
            (project_path / "requirements.txt").exists()  # Pinned versions
        )
        has_transitive = any(not dep.is_direct for dep in result.dependencies)
        
        if has_lock_file and has_transitive:
            scan_confidence = "High"
        elif has_lock_file or result.total_dependencies > 3:
            scan_confidence = "Medium"
        else:
            scan_confidence = "Low"
        
        # Classify dependencies by risk
        from ..scanners import PackageClassifier
        classifier = PackageClassifier()
        classified = classifier.classify_dependencies(result.dependencies)
        security_relevant_deps = classified["security_relevant"]
        conditionally_relevant_deps = classified["conditionally_relevant"]
        support_deps = classified["support"]
        
        html_output = template.render(
            scan_time=result.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            project_path=result.project_path,
            total_dependencies=result.total_dependencies,
            total_vulnerabilities=result.total_vulnerabilities,
            typosquat_count=len(result.typosquat_matches),
            license_issues=len(result.license_issues),
            vulnerabilities=result.vulnerabilities,
            typosquats=result.typosquat_matches,
            license_list=result.license_issues,
            dependencies=result.dependencies,
            has_issues=result.has_issues,
            reputation_scores=result.reputation_scores,
            # Executive summary data
            security_posture=security_posture,
            critical_count=critical_count,
            critical_actual_count=critical_actual_count,
            high_count=high_count,
            unknown_count=unknown_count,
            affected_packages=affected_packages,
            has_fix_available=has_fix_available,
            max_ses_package=max_ses_package,
            max_ses_score=round(max_ses_score, 1) if max_ses_score else 0,
            ses_scores=getattr(result, 'ses_scores', {}),
            # Scan confidence
            scan_confidence=scan_confidence,
            has_lock_file=has_lock_file,
            # Risk grouping
            security_relevant_deps=security_relevant_deps,
            conditionally_relevant_deps=conditionally_relevant_deps,
            support_deps=support_deps,
        )
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_output)
        
        return html_output
