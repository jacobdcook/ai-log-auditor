#!/usr/bin/env python3
"""
AI-Powered Log Auditor
A cybersecurity tool that uses pattern matching and AI (LLM) to analyze log files
and identify potential security threats, explaining why specific log entries are suspicious.
"""

import re
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from enum import Enum
import sys
import html

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from groq import Groq
except ImportError:
    Groq = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
except ImportError:
    print("ERROR: reportlab library not installed. Run: pip install reportlab")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("⚠️  Warning: PyYAML not installed. Config file support disabled. Run: pip install pyyaml")


class LogFormat(Enum):
    """Supported log file formats."""
    APACHE = "apache"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    GENERIC = "generic"  # Fallback for unknown formats


# Default attack pattern definitions
DEFAULT_ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bOR\b.*['\"].*['\"].*\b=\b.*['\"].*['\"])",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bINSERT\b.*\bINTO\b.*\bVALUES\b)",
        r"(\bDELETE\b.*\bFROM\b)",
        r"(;\s*DROP\s+TABLE)",
        r"(;\s*DELETE\s+FROM)",
        r"(\bexec\s*\(.*select)",
        r"(/\*.*\*/)",
        r"(--.*)",
    ],
    "Cross-Site Scripting (XSS)": [
        r"(<script[^>]*>.*?</script>)",
        r"(javascript:)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(onclick\s*=)",
        r"(<img[^>]*src\s*=\s*['\"]javascript:)",
        r"(<iframe[^>]*>)",
        r"(alert\s*\(.*\))",
        r"(document\.cookie)",
        r"(eval\s*\()",
    ],
    "Command Injection": [
        r"(;\s*(cat|ls|rm|wget|curl|nc|netcat)\s)",
        r"(\|\s*(cat|ls|rm|wget|curl|nc|netcat)\s)",
        r"(`[^`]+`)",
        r"(\$\{[^}]+\})",
        r"(&&\s*(cat|ls|rm|wget|curl|nc|netcat)\s)",
        r"(>.*\.(sh|exe|bat|ps1))",
    ],
    "Path Traversal": [
        r"(\.\.\/\.\.\/)",
        r"(\.\.\\\.\.\\)",
        r"(\.\.\/\.\.\/\.\.\/)",
        r"(\.\.%2F)",
        r"(\.\.%5C)",
        r"(\.\.%252F)",
        r"(\/etc\/passwd)",
        r"(\/windows\/system32)",
        r"(C:\\Windows\\System32)",
    ],
    "Authentication Bypass": [
        r"(admin\s*'?\s*OR\s*'1'\s*=\s*'1)",
        r"(password\s*=\s*['\"]\s*OR\s*['\"]\s*=\s*['\"])",
        r"(\btrue\b|\b1\b)\s*(--|\#|\/\*)",
        r"(bypass|admin|root|administrator)",
    ],
    "File Inclusion": [
        r"(include\s*\([^)]*\.\.)",
        r"(require\s*\([^)]*\.\.)",
        r"(include_once\s*\([^)]*\.\.)",
        r"(require_once\s*\([^)]*\.\.)",
        r"(php://filter)",
        r"(data://text/plain)",
    ],
}


def detect_log_format(log_path: Path, sample_lines: int = 10) -> LogFormat:
    """
    Detect the log file format by analyzing sample lines.
    
    Args:
        log_path: Path to the log file
        sample_lines: Number of lines to sample for detection
        
    Returns:
        Detected LogFormat enum
    """
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = []
            for _ in range(sample_lines):
                line = f.readline()
                if not line:
                    break
                lines.append(line.strip())
        
        if not lines:
            return LogFormat.GENERIC
        
        # Apache access log detection (IP - - [timestamp] "method path" status size)
        apache_pattern = r'^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[.*\]\s+"[A-Z]+\s+.*"\s+\d+\s+\d+'
        if any(re.match(apache_pattern, line) for line in lines):
            return LogFormat.APACHE
        
        # Syslog detection (timestamp hostname service: message)
        syslog_pattern = r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s+.*'
        if any(re.match(syslog_pattern, line) for line in lines):
            return LogFormat.SYSLOG
        
        # Windows Event Log detection (EventID, EventType, etc.)
        windows_patterns = [
            r'EventID\s*=\s*\d+',
            r'EventType\s*=\s*\w+',
            r'<EventID>',
            r'LogName:\s*\w+',
        ]
        if any(any(re.search(p, line, re.IGNORECASE) for p in windows_patterns) for line in lines):
            return LogFormat.WINDOWS_EVENT
        
        return LogFormat.GENERIC
    except Exception:
        return LogFormat.GENERIC


def parse_log_line(line: str, log_format: LogFormat) -> Dict:
    """
    Parse a log line based on its format and extract relevant fields.
    
    Args:
        line: Raw log line
        log_format: Detected log format
        
    Returns:
        Dictionary with parsed fields (ip, timestamp, message, etc.)
    """
    parsed = {
        "raw": line.strip(),
        "format": log_format.value,
        "ip": None,
        "timestamp": None,
        "message": line.strip(),
    }
    
    if log_format == LogFormat.APACHE:
        # Apache: IP - - [timestamp] "method path" status size "user-agent"
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"', line)
        if match:
            parsed["ip"] = match.group(1)
            parsed["timestamp"] = match.group(2)
            parsed["method_path"] = match.group(3)
            parsed["status"] = match.group(4)
            parsed["message"] = match.group(3)  # Use method+path for pattern matching
    
    elif log_format == LogFormat.SYSLOG:
        # Syslog: timestamp hostname service: message
        match = re.match(r'^[A-Z][a-z]{2}\s+\d+\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)', line)
        if match:
            parsed["timestamp"] = match.group(1)
            parsed["hostname"] = match.group(2)
            parsed["service"] = match.group(3)
            parsed["message"] = match.group(4)
    
    elif log_format == LogFormat.WINDOWS_EVENT:
        # Windows Event Log - extract EventID and message
        event_id_match = re.search(r'EventID[:\s=]+(\d+)', line, re.IGNORECASE)
        if event_id_match:
            parsed["event_id"] = event_id_match.group(1)
        # Extract message content
        message_match = re.search(r'Message[:\s=]+(.*?)(?:\n|$)', line, re.IGNORECASE | re.DOTALL)
        if message_match:
            parsed["message"] = message_match.group(1).strip()
    
    return parsed


def load_config_file(config_path: Optional[Path] = None) -> Dict:
    """
    Load attack patterns from a configuration file.
    
    Args:
        config_path: Path to config file (YAML or JSON). If None, uses default patterns.
        
    Returns:
        Dictionary of attack patterns matching DEFAULT_ATTACK_PATTERNS structure
    """
    if config_path is None or not config_path.exists():
        return DEFAULT_ATTACK_PATTERNS
    
    try:
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() == '.yaml' or config_path.suffix.lower() == '.yml':
                if yaml is None:
                    print("⚠️  Warning: PyYAML not installed. Using default patterns.")
                    return DEFAULT_ATTACK_PATTERNS
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
        
        # Validate and merge with defaults
        if "attack_patterns" in config:
            # Merge custom patterns with defaults
            merged = DEFAULT_ATTACK_PATTERNS.copy()
            for attack_type, patterns in config["attack_patterns"].items():
                if isinstance(patterns, list):
                    merged[attack_type] = patterns
                elif isinstance(patterns, dict) and "patterns" in patterns:
                    merged[attack_type] = patterns["patterns"]
            return merged
        
        return DEFAULT_ATTACK_PATTERNS
    except Exception as e:
        print(f"⚠️  Warning: Error loading config file: {e}. Using default patterns.")
        return DEFAULT_ATTACK_PATTERNS


class LogAuditor:
    """Main log auditor class that scans logs and uses AI to explain threats."""
    
    def __init__(self, api_key: str = None, use_groq: bool = False, config_file: Path = None):
        """
        Initialize the log auditor.
        
        Args:
            api_key: API key (OpenAI or Groq). If None, will try to read from environment.
            use_groq: If True, use Groq instead of OpenAI (free alternative)
            config_file: Path to configuration file with custom attack patterns (YAML or JSON)
        """
        self.api_key = api_key
        self.use_groq = use_groq
        self.openai_client = None
        self.groq_client = None
        self.config_file = config_file
        self.attack_patterns = load_config_file(config_file)
        
        import os
        
        if use_groq:
            if Groq is None:
                print("⚠️  Warning: Groq library not installed. Run: pip install groq")
                return
            
            if api_key:
                self.groq_client = Groq(api_key=api_key)
            else:
                # Try to load from environment
                api_key = os.getenv("GROQ_API_KEY")
                if api_key:
                    self.groq_client = Groq(api_key=api_key)
        else:
            if OpenAI is None:
                print("⚠️  Warning: OpenAI library not installed. Run: pip install openai")
                return
            
            if api_key:
                self.openai_client = OpenAI(api_key=api_key)
            else:
                # Try to load from environment or config file
                api_key = os.getenv("OPENAI_API_KEY")
                if api_key:
                    self.openai_client = OpenAI(api_key=api_key)
        
        self.suspicious_lines: List[Dict] = []
        self.scan_stats = {
            "total_lines": 0,
            "suspicious_lines": 0,
            "by_attack_type": {}
        }
    
    def scan_log_file(self, log_path: Path, log_format: Optional[LogFormat] = None) -> List[Dict]:
        """
        Scan a log file for attack patterns.
        
        Args:
            log_path: Path to the log file
            log_format: Optional log format. If None, will auto-detect.
            
        Returns:
            List of dictionaries containing suspicious log entries
        """
        print(f"📄 Scanning log file: {log_path}")
        
        # Auto-detect log format if not specified
        if log_format is None:
            print(f"🔍 Detecting log format...")
            log_format = detect_log_format(log_path)
            print(f"   Detected format: {log_format.value.upper()}\n")
        else:
            print(f"   Using format: {log_format.value.upper()}\n")
        
        print(f"🔍 Analyzing for attack patterns...\n")
        
        suspicious_lines = []
        line_number = 0
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_number += 1
                    self.scan_stats["total_lines"] += 1
                    
                    # Parse log line based on format
                    parsed = parse_log_line(line, log_format)
                    # Use parsed message for pattern matching (more accurate)
                    search_text = parsed.get("message", line)
                    
                    # Check each attack pattern
                    matched = False
                    for attack_type, patterns in self.attack_patterns.items():
                        if matched:
                            break
                        for pattern in patterns:
                            if re.search(pattern, search_text, re.IGNORECASE):
                                # Found suspicious pattern
                                suspicious_lines.append({
                                    "line_number": line_number,
                                    "line_content": line.strip(),
                                    "parsed": parsed,
                                    "attack_type": attack_type,
                                    "matched_pattern": pattern,
                                    "log_format": log_format.value,
                                })

                                # Update stats
                                if attack_type not in self.scan_stats["by_attack_type"]:
                                    self.scan_stats["by_attack_type"][attack_type] = 0
                                self.scan_stats["by_attack_type"][attack_type] += 1

                                # Only count each line once (break after first match)
                                matched = True
                                break
        
        except FileNotFoundError:
            print(f"❌ ERROR: File not found: {log_path}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ ERROR reading file: {e}")
            sys.exit(1)
        
        self.suspicious_lines = suspicious_lines
        self.scan_stats["suspicious_lines"] = len(suspicious_lines)
        
        print(f"✅ Scan complete!")
        print(f"   Total lines scanned: {self.scan_stats['total_lines']}")
        print(f"   Suspicious lines found: {self.scan_stats['suspicious_lines']}\n")
        
        return suspicious_lines
    
    def explain_with_ai(self, log_entry: Dict, max_explanations: int = 10) -> str:
        """
        Use AI to explain why a log entry is suspicious.
        
        Args:
            log_entry: Dictionary containing log entry details
            max_explanations: Maximum number of AI explanations to generate (to save API costs)
            
        Returns:
            AI-generated explanation string
        """
        # Check which AI service is available
        if self.use_groq and not self.groq_client:
            return "⚠️  Groq API key not configured. Set GROQ_API_KEY environment variable or use --api-key."
        elif not self.use_groq and not self.openai_client:
            return "⚠️  OpenAI API key not configured. Set OPENAI_API_KEY environment variable or use --api-key."
        
        # Limit AI explanations to avoid high API costs
        if len([e for e in self.suspicious_lines if "ai_explanation" in e]) >= max_explanations:
            return "⚠️  AI explanation limit reached. Use --max-explanations to increase."
        
        try:
            prompt = f"""You are a cybersecurity expert analyzing a suspicious log entry. 

Log Entry (Line {log_entry['line_number']}):
{log_entry['line_content']}

Detected Attack Type: {log_entry['attack_type']}
Matched Pattern: {log_entry['matched_pattern']}

Provide a brief, professional explanation (2-3 sentences) of:
1. What attack technique this log entry represents
2. What the attacker is attempting to accomplish
3. The potential impact if this attack succeeds

Be specific and technical, but concise."""

            messages = [
                {"role": "system", "content": "You are a cybersecurity expert specializing in log analysis and threat detection."},
                {"role": "user", "content": prompt}
            ]
            
            if self.use_groq and self.groq_client:
                # Use Groq (free and fast!)
                response = self.groq_client.chat.completions.create(
                    model="llama-3.3-70b-versatile",  # Groq's current free model
                    messages=messages,
                    max_tokens=200,
                    temperature=0.7
                )
            else:
                # Use OpenAI
                response = self.openai_client.chat.completions.create(
                    model="gpt-4o-mini",  # Using cheaper model
                    messages=messages,
                    max_tokens=200,
                    temperature=0.7
                )
            
            explanation = response.choices[0].message.content.strip()
            return explanation
        
        except Exception as e:
            return f"⚠️  Error generating AI explanation: {str(e)}"
    
    def generate_report_text(self, output_path: Path = None) -> str:
        """Generate a text report of findings."""
        report = []
        report.append("=" * 80)
        report.append("AI-POWERED LOG AUDITOR - SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary statistics
        report.append("SUMMARY STATISTICS")
        report.append("-" * 80)
        report.append(f"Total log lines scanned: {self.scan_stats['total_lines']}")
        report.append(f"Suspicious lines detected: {self.scan_stats['suspicious_lines']}")
        report.append("")
        
        if self.scan_stats["by_attack_type"]:
            report.append("ATTACKS BY TYPE:")
            for attack_type, count in sorted(self.scan_stats["by_attack_type"].items(), 
                                            key=lambda x: x[1], reverse=True):
                report.append(f"  {attack_type}: {count}")
            report.append("")
        
        # Detailed findings
        if self.suspicious_lines:
            report.append("DETAILED FINDINGS")
            report.append("-" * 80)
            report.append("")
            
            for entry in self.suspicious_lines[:50]:  # Limit to first 50 for text report
                report.append(f"[Line {entry['line_number']}] {entry['attack_type']}")
                report.append(f"Pattern: {entry['matched_pattern']}")
                report.append(f"Log Entry: {entry['line_content'][:200]}")  # Truncate long lines
                
                if "ai_explanation" in entry:
                    report.append(f"AI Analysis: {entry['ai_explanation']}")
                
                report.append("")
        else:
            report.append("✅ No suspicious activity detected!")
            report.append("")
        
        report.append("=" * 80)
        report_text = "\n".join(report)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_text)
            print(f"📄 Text report saved to: {output_path}")
        
        return report_text
    
    def generate_pdf_report(self, output_path: Path):
        """Generate a professional PDF security report."""
        print(f"📊 Generating PDF report: {output_path}")
        
        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a472a'),
            spaceAfter=30,
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2d5016'),
            spaceAfter=12,
        )
        
        # Title
        story.append(Paragraph("AI-Powered Log Auditor", title_style))
        story.append(Paragraph("Security Analysis Report", styles['Heading2']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary Statistics
        story.append(Paragraph("Summary Statistics", heading_style))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Lines Scanned', str(self.scan_stats['total_lines'])],
            ['Suspicious Lines Detected', str(self.scan_stats['suspicious_lines'])],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Attack Types Breakdown
        if self.scan_stats["by_attack_type"]:
            story.append(Paragraph("Attacks by Type", heading_style))
            attack_data = [['Attack Type', 'Count']]
            for attack_type, count in sorted(self.scan_stats["by_attack_type"].items(), 
                                            key=lambda x: x[1], reverse=True):
                attack_data.append([attack_type, str(count)])
            
            attack_table = Table(attack_data, colWidths=[4*inch, 1*inch])
            attack_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(attack_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Detailed Findings
        if self.suspicious_lines:
            story.append(Paragraph("Detailed Findings", heading_style))
            
            for i, entry in enumerate(self.suspicious_lines[:30], 1):  # Limit to 30 for PDF
                story.append(Paragraph(f"<b>Finding #{i}: Line {entry['line_number']} - {entry['attack_type']}</b>", 
                                      styles['Heading3']))
                pattern_escaped = html.escape(entry['matched_pattern'])
                story.append(Paragraph(f"<b>Pattern:</b> <font face='Courier'>{pattern_escaped}</font>", styles['Normal']))
                
                # Truncate long log lines and escape HTML to prevent parsing errors
                log_content = entry['line_content'][:300] + "..." if len(entry['line_content']) > 300 else entry['line_content']
                log_content_escaped = html.escape(log_content)  # Escape HTML chars in log content
                story.append(Paragraph(f"<b>Log Entry:</b> <font face='Courier'>{log_content_escaped}</font>", styles['Normal']))
                
                if "ai_explanation" in entry:
                    ai_explanation_escaped = html.escape(entry['ai_explanation'])
                    story.append(Paragraph(f"<b>AI Analysis:</b> {ai_explanation_escaped}", styles['Normal']))
                
                story.append(Spacer(1, 0.15*inch))
        else:
            story.append(Paragraph("✅ No suspicious activity detected!", styles['Normal']))
        
        doc.build(story)
        print(f"✅ PDF report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Powered Log Auditor - Analyze log files for security threats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s access.log
  %(prog)s access.log --ai --api-key YOUR_KEY
  %(prog)s access.log --pdf report.pdf --max-explanations 5
        """
    )
    
    parser.add_argument('log_file', type=str, help='Path to the log file to analyze')
    parser.add_argument('--api-key', type=str, help='API key (OpenAI or Groq - set via env var if not provided)')
    parser.add_argument('--ai', action='store_true', 
                       help='Use AI to explain suspicious log entries (requires API key)')
    parser.add_argument('--groq', action='store_true',
                       help='Use Groq AI instead of OpenAI (free alternative, requires GROQ_API_KEY)')
    parser.add_argument('--max-explanations', type=int, default=10,
                       help='Maximum number of AI explanations to generate (default: 10)')
    parser.add_argument('--pdf', type=str, metavar='OUTPUT_FILE',
                       help='Generate PDF report (specify output filename)')
    parser.add_argument('--text-report', type=str, metavar='OUTPUT_FILE',
                       help='Generate text report (specify output filename)')
    parser.add_argument('--config', type=str, metavar='CONFIG_FILE',
                       help='Path to configuration file with custom attack patterns (YAML or JSON)')
    parser.add_argument('--format', type=str, choices=['apache', 'syslog', 'windows_event', 'auto'],
                       default='auto', help='Log file format (default: auto-detect)')
    
    args = parser.parse_args()
    
    # Parse log format
    format_map = {
        'apache': LogFormat.APACHE,
        'syslog': LogFormat.SYSLOG,
        'windows_event': LogFormat.WINDOWS_EVENT,
        'auto': None
    }
    log_format = format_map[args.format]
    
    # Initialize auditor
    config_path = Path(args.config) if args.config else None
    auditor = LogAuditor(api_key=args.api_key, use_groq=args.groq, config_file=config_path)
    
    # Scan log file
    log_path = Path(args.log_file)
    suspicious_lines = auditor.scan_log_file(log_path, log_format=log_format)
    
    # Use AI to explain suspicious entries
    ai_client_available = (auditor.openai_client is not None) or (auditor.groq_client is not None)
    
    if args.ai and ai_client_available:
        ai_provider = "Groq" if args.groq else "OpenAI"
        print(f"🤖 Generating AI explanations using {ai_provider}...")
        explained_count = 0
        for entry in suspicious_lines[:args.max_explanations]:
            explanation = auditor.explain_with_ai(entry, max_explanations=args.max_explanations)
            entry['ai_explanation'] = explanation
            explained_count += 1
            if explained_count % 5 == 0:
                print(f"   Processed {explained_count}/{min(args.max_explanations, len(suspicious_lines))} explanations...")
        print(f"✅ Generated {explained_count} AI explanations\n")
    elif args.ai and not ai_client_available:
        print("⚠️  Warning: --ai flag used but no API key provided.")
        if args.groq:
            print("   Set GROQ_API_KEY environment variable or use --api-key with --groq")
        else:
            print("   Set OPENAI_API_KEY environment variable or use --api-key")
        print("   Skipping AI analysis.\n")
    
    # Generate reports
    if args.text_report:
        auditor.generate_report_text(Path(args.text_report))
    
    if args.pdf:
        auditor.generate_pdf_report(Path(args.pdf))
    else:
        # Print summary to console
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        for entry in suspicious_lines[:10]:  # Show first 10 in console
            print(f"\n[Line {entry['line_number']}] {entry['attack_type']}")
            print(f"  Pattern: {entry['matched_pattern']}")
            print(f"  Entry: {entry['line_content'][:150]}")
            if "ai_explanation" in entry:
                print(f"  AI: {entry['ai_explanation']}")
        
        if len(suspicious_lines) > 10:
            print(f"\n... and {len(suspicious_lines) - 10} more suspicious entries.")
            print("Use --pdf or --text-report to see full analysis.")


if __name__ == "__main__":
    main()
