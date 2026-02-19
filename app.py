"""
ShipSecure - Startup Security Scanner
A passive security assessment tool for founders who ship fast.
Only scan domains you own or have permission to test.
"""

import streamlit as st
import ssl
import socket
import requests
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime, timezone
import concurrent.futures
from dataclasses import dataclass
from typing import Optional
import re

# ============== Configuration ==============
st.set_page_config(
    page_title="ShipSecure | Startup Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============== Custom CSS ==============
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
    --bg-dark: #0a0a0f;
    --bg-card: #12121a;
    --accent-green: #00ff88;
    --accent-red: #ff4757;
    --accent-yellow: #ffd93d;
    --accent-blue: #4dabf7;
    --text-primary: #e4e4e7;
    --text-muted: #71717a;
}

.stApp {
    background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
    font-family: 'Space Grotesk', sans-serif;
}

.main-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 3.5rem;
    font-weight: 700;
    background: linear-gradient(90deg, #00ff88, #4dabf7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-align: center;
    margin-bottom: 0;
    letter-spacing: -2px;
}

.subtitle {
    text-align: center;
    color: var(--text-muted);
    font-size: 1.1rem;
    margin-top: 0.5rem;
    margin-bottom: 2rem;
}

.risk-score-container {
    background: var(--bg-card);
    border-radius: 20px;
    padding: 2rem;
    text-align: center;
    border: 1px solid #2a2a3a;
    margin: 1rem 0;
}

.risk-score {
    font-family: 'JetBrains Mono', monospace;
    font-size: 5rem;
    font-weight: 700;
    line-height: 1;
}

.risk-critical { color: #ff4757; }
.risk-high { color: #ff6b35; }
.risk-medium { color: #ffd93d; }
.risk-low { color: #00ff88; }

.risk-label {
    font-size: 1.5rem;
    font-weight: 600;
    margin-top: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 3px;
}

.finding-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    margin: 1rem 0;
    border-left: 4px solid;
}

.finding-critical { border-color: #ff4757; }
.finding-high { border-color: #ff6b35; }
.finding-medium { border-color: #ffd93d; }
.finding-low { border-color: #00ff88; }
.finding-info { border-color: #4dabf7; }

.finding-title {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 1.1rem;
    margin-bottom: 0.5rem;
}

.finding-desc {
    color: var(--text-muted);
    font-size: 0.95rem;
    margin-bottom: 1rem;
}

.fix-box {
    background: #1a2f1a;
    border: 1px solid #2a4a2a;
    border-radius: 8px;
    padding: 1rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
}

.stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin: 2rem 0;
}

.stat-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    border: 1px solid #2a2a3a;
}

.stat-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--accent-blue);
}

.stat-label {
    color: var(--text-muted);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 0.5rem;
}

.disclaimer {
    background: #1a1a2e;
    border: 1px solid #2a2a3a;
    border-radius: 8px;
    padding: 1rem;
    font-size: 0.8rem;
    color: var(--text-muted);
    text-align: center;
    margin-top: 2rem;
}

/* Hide Streamlit branding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Input styling */
.stTextInput input {
    background: var(--bg-card) !important;
    border: 2px solid #2a2a3a !important;
    border-radius: 12px !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', monospace !important;
    padding: 1rem !important;
    font-size: 1.1rem !important;
}

.stTextInput input:focus {
    border-color: var(--accent-green) !important;
    box-shadow: 0 0 20px rgba(0, 255, 136, 0.2) !important;
}

/* Button styling */
.stButton > button {
    background: linear-gradient(90deg, #00ff88, #00cc6a) !important;
    color: #0a0a0f !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 0.75rem 2rem !important;
    font-size: 1rem !important;
    letter-spacing: 1px !important;
    transition: all 0.3s ease !important;
}

.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3) !important;
}

/* Progress bar */
.stProgress > div > div {
    background: linear-gradient(90deg, #00ff88, #4dabf7) !important;
}
</style>
""", unsafe_allow_html=True)


# ============== Data Classes ==============
@dataclass
class Finding:
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    fix: str
    category: str
    points: int  # deducted from score


@dataclass
class ScanResult:
    domain: str
    score: int
    grade: str
    findings: list
    tls_info: dict
    headers_info: dict
    dns_info: dict
    scan_time: float


# ============== Scanner Functions ==============

def clean_domain(input_str: str) -> str:
    """Extract clean domain from input."""
    input_str = input_str.strip().lower()
    if input_str.startswith(('http://', 'https://')):
        parsed = urlparse(input_str)
        return parsed.netloc or parsed.path
    return input_str.split('/')[0]


def check_tls(domain: str) -> tuple[dict, list]:
    """Check TLS/SSL configuration."""
    findings = []
    info = {
        'valid': False,
        'version': None,
        'expires': None,
        'issuer': None,
        'days_until_expiry': None,
        'grade': 'F'
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info['valid'] = True
                info['version'] = ssock.version()
                
                # Parse expiry
                expires_str = cert.get('notAfter', '')
                if expires_str:
                    expires = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
                    info['expires'] = expires.strftime('%Y-%m-%d')
                    days_left = (expires - datetime.now()).days
                    info['days_until_expiry'] = days_left
                    
                    if days_left < 0:
                        findings.append(Finding(
                            title="SSL Certificate Expired",
                            severity="critical",
                            description=f"Your SSL certificate expired {abs(days_left)} days ago. Browsers will show security warnings.",
                            fix="Renew your certificate immediately via Let's Encrypt (free) or your certificate provider.",
                            category="TLS",
                            points=40
                        ))
                    elif days_left < 14:
                        findings.append(Finding(
                            title="SSL Certificate Expiring Soon",
                            severity="high",
                            description=f"Certificate expires in {days_left} days. Risk of unexpected outage.",
                            fix="Renew now. Consider enabling auto-renewal with certbot: `certbot renew --dry-run`",
                            category="TLS",
                            points=20
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title="SSL Certificate Expiring",
                            severity="medium",
                            description=f"Certificate expires in {days_left} days.",
                            fix="Schedule renewal. Enable auto-renewal to avoid manual work.",
                            category="TLS",
                            points=10
                        ))
                
                # Check TLS version
                if info['version'] in ['TLSv1', 'TLSv1.1']:
                    findings.append(Finding(
                        title="Outdated TLS Version",
                        severity="high",
                        description=f"Using {info['version']} which is deprecated and insecure.",
                        fix="Configure server to use TLS 1.2+ only. Disable TLS 1.0/1.1.",
                        category="TLS",
                        points=25
                    ))
                
                # Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                info['issuer'] = issuer_dict.get('organizationName', 'Unknown')
                
                # Grade calculation
                if info['version'] in ['TLSv1.2', 'TLSv1.3'] and days_left > 30:
                    info['grade'] = 'A' if info['version'] == 'TLSv1.3' else 'B+'
                elif days_left > 14:
                    info['grade'] = 'B'
                elif days_left > 0:
                    info['grade'] = 'C'
                else:
                    info['grade'] = 'F'
                    
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            title="Invalid SSL Certificate",
            severity="critical",
            description=f"Certificate validation failed: {str(e)[:100]}",
            fix="Check certificate chain, ensure correct domain, or renew if self-signed.",
            category="TLS",
            points=40
        ))
    except socket.timeout:
        findings.append(Finding(
            title="HTTPS Connection Timeout",
            severity="high",
            description="Could not establish HTTPS connection within 10 seconds.",
            fix="Verify port 443 is open and SSL is properly configured.",
            category="TLS",
            points=30
        ))
    except Exception as e:
        findings.append(Finding(
            title="HTTPS Not Available",
            severity="critical",
            description=f"Could not connect via HTTPS: {str(e)[:100]}",
            fix="Enable HTTPS on your server. Use Let's Encrypt for free certificates.",
            category="TLS",
            points=40
        ))
    
    return info, findings


def check_security_headers(domain: str) -> tuple[dict, list]:
    """Check HTTP security headers."""
    findings = []
    headers_found = {}
    
    required_headers = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'desc': 'HSTS not enabled. Users can be downgraded to HTTP.',
            'fix': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'points': 20
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'desc': 'Missing X-Content-Type-Options. Vulnerable to MIME-sniffing attacks.',
            'fix': 'Add header: X-Content-Type-Options: nosniff',
            'points': 10
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'desc': 'Missing X-Frame-Options. Vulnerable to clickjacking.',
            'fix': 'Add header: X-Frame-Options: DENY (or SAMEORIGIN)',
            'points': 10
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'desc': 'No Content-Security-Policy. Vulnerable to XSS attacks.',
            'fix': "Start with: Content-Security-Policy: default-src 'self'",
            'points': 15
        },
        'X-XSS-Protection': {
            'severity': 'low',
            'desc': 'Missing X-XSS-Protection (legacy browsers).',
            'fix': 'Add header: X-XSS-Protection: 1; mode=block',
            'points': 5
        },
        'Referrer-Policy': {
            'severity': 'low',
            'desc': 'No Referrer-Policy. May leak sensitive URLs.',
            'fix': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'points': 5
        },
        'Permissions-Policy': {
            'severity': 'low',
            'desc': 'No Permissions-Policy. Browser features unrestricted.',
            'fix': 'Add header: Permissions-Policy: geolocation=(), microphone=()',
            'points': 5
        }
    }
    
    try:
        response = requests.get(f'https://{domain}', timeout=10, allow_redirects=True)
        
        for header, config in required_headers.items():
            value = response.headers.get(header)
            headers_found[header] = value
            
            if not value:
                findings.append(Finding(
                    title=f"Missing {header}",
                    severity=config['severity'],
                    description=config['desc'],
                    fix=config['fix'],
                    category="Headers",
                    points=config['points']
                ))
        
        # Check for information disclosure
        server = response.headers.get('Server', '')
        if server and any(v in server.lower() for v in ['apache', 'nginx', 'iis']):
            if any(c.isdigit() for c in server):
                findings.append(Finding(
                    title="Server Version Disclosed",
                    severity="low",
                    description=f"Server header reveals: {server}. Aids attackers.",
                    fix="Configure server to hide version. Nginx: server_tokens off;",
                    category="Headers",
                    points=5
                ))
        
        x_powered = response.headers.get('X-Powered-By', '')
        if x_powered:
            findings.append(Finding(
                title="Technology Stack Disclosed",
                severity="low",
                description=f"X-Powered-By reveals: {x_powered}",
                fix="Remove X-Powered-By header from server configuration.",
                category="Headers",
                points=5
            ))
            
    except requests.exceptions.SSLError:
        findings.append(Finding(
            title="SSL Error During Header Check",
            severity="high",
            description="Could not establish secure connection to check headers.",
            fix="Fix SSL configuration first, then re-run scan.",
            category="Headers",
            points=20
        ))
    except Exception as e:
        findings.append(Finding(
            title="Header Check Failed",
            severity="info",
            description=f"Could not retrieve headers: {str(e)[:100]}",
            fix="Ensure the site is accessible.",
            category="Headers",
            points=0
        ))
    
    return headers_found, findings


def check_dns_security(domain: str) -> tuple[dict, list]:
    """Check DNS security records (SPF, DMARC, DKIM indicator)."""
    findings = []
    dns_info = {
        'spf': None,
        'dmarc': None,
        'has_dkim': False,
        'nameservers': []
    }
    
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']  # Use public DNS
    resolver.timeout = 5
    resolver.lifetime = 10
    
    # Check SPF
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for record in txt_records:
            txt = str(record).strip('"')
            if txt.startswith('v=spf1'):
                dns_info['spf'] = txt
                if '-all' not in txt and '~all' not in txt:
                    findings.append(Finding(
                        title="Weak SPF Policy",
                        severity="medium",
                        description="SPF record found but not enforcing. Email spoofing possible.",
                        fix="Update SPF to end with '-all' (hard fail) instead of '+all' or '?all'",
                        category="DNS",
                        points=10
                    ))
                break
        
        if not dns_info['spf']:
            findings.append(Finding(
                title="Missing SPF Record",
                severity="high",
                description="No SPF record. Anyone can spoof emails from your domain.",
                fix="Add TXT record: v=spf1 include:_spf.google.com -all (adjust for your email provider)",
                category="DNS",
                points=15
            ))
    except Exception:
        findings.append(Finding(
            title="Missing SPF Record",
            severity="high",
            description="No SPF record found. Email spoofing is possible.",
            fix="Add TXT record: v=spf1 include:_spf.google.com -all",
            category="DNS",
            points=15
        ))
    
    # Check DMARC
    try:
        dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_records:
            txt = str(record).strip('"')
            if 'v=DMARC1' in txt:
                dns_info['dmarc'] = txt
                if 'p=none' in txt:
                    findings.append(Finding(
                        title="DMARC Policy Not Enforcing",
                        severity="medium",
                        description="DMARC exists but set to 'none'. No protection active.",
                        fix="Change policy to 'p=quarantine' or 'p=reject' after testing.",
                        category="DNS",
                        points=10
                    ))
                break
    except Exception:
        findings.append(Finding(
            title="Missing DMARC Record",
            severity="high",
            description="No DMARC policy. Cannot prevent email spoofing abuse.",
            fix="Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
            category="DNS",
            points=15
        ))
    
    # Check for DKIM (common selectors)
    common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail']
    for selector in common_selectors:
        try:
            resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
            dns_info['has_dkim'] = True
            break
        except Exception:
            continue
    
    if not dns_info['has_dkim']:
        findings.append(Finding(
            title="DKIM Not Detected",
            severity="medium",
            description="No DKIM records found (checked common selectors). Email authenticity unverified.",
            fix="Enable DKIM in your email provider settings. Google Workspace/O365 have guides.",
            category="DNS",
            points=10
        ))
    
    # Get nameservers
    try:
        ns_records = resolver.resolve(domain, 'NS')
        dns_info['nameservers'] = [str(ns).rstrip('.') for ns in ns_records]
    except Exception:
        pass
    
    return dns_info, findings


def calculate_score(findings: list) -> tuple[int, str]:
    """Calculate security score from findings."""
    score = 100
    for finding in findings:
        score -= finding.points
    
    score = max(0, min(100, score))
    
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    
    return score, grade


def run_scan(domain: str) -> ScanResult:
    """Run all security checks."""
    start_time = datetime.now()
    all_findings = []
    
    # Run checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        tls_future = executor.submit(check_tls, domain)
        headers_future = executor.submit(check_security_headers, domain)
        dns_future = executor.submit(check_dns_security, domain)
        
        tls_info, tls_findings = tls_future.result()
        headers_info, headers_findings = headers_future.result()
        dns_info, dns_findings = dns_future.result()
    
    all_findings.extend(tls_findings)
    all_findings.extend(headers_findings)
    all_findings.extend(dns_findings)
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda x: severity_order.get(x.severity, 5))
    
    score, grade = calculate_score(all_findings)
    scan_time = (datetime.now() - start_time).total_seconds()
    
    return ScanResult(
        domain=domain,
        score=score,
        grade=grade,
        findings=all_findings,
        tls_info=tls_info,
        headers_info=headers_info,
        dns_info=dns_info,
        scan_time=scan_time
    )


# ============== UI Components ==============

def render_finding(finding: Finding):
    """Render a single finding card."""
    severity_colors = {
        'critical': '#ff4757',
        'high': '#ff6b35',
        'medium': '#ffd93d',
        'low': '#00ff88',
        'info': '#4dabf7'
    }
    color = severity_colors.get(finding.severity, '#4dabf7')
    
    st.markdown(f"""
    <div class="finding-card finding-{finding.severity}">
        <div class="finding-title" style="color: {color};">
            [{finding.severity.upper()}] {finding.title}
        </div>
        <div class="finding-desc">{finding.description}</div>
        <div class="fix-box">
            💡 <strong>Fix:</strong> {finding.fix}
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_score(score: int, grade: str):
    """Render the main score display."""
    if score >= 80:
        color_class = "risk-low"
        label = "Good"
    elif score >= 60:
        color_class = "risk-medium"
        label = "Needs Work"
    elif score >= 40:
        color_class = "risk-high"
        label = "At Risk"
    else:
        color_class = "risk-critical"
        label = "Critical"
    
    st.markdown(f"""
    <div class="risk-score-container">
        <div class="risk-score {color_class}">{score}</div>
        <div class="risk-label" style="color: inherit;">{label}</div>
        <div style="color: var(--text-muted); margin-top: 1rem;">Grade: {grade}</div>
    </div>
    """, unsafe_allow_html=True)


# ============== Main App ==============

def main():
    st.markdown('<h1 class="main-title">🛡️ ShipSecure</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Instant security assessment for startups that ship fast</p>', unsafe_allow_html=True)
    
    # Disclaimer
    st.markdown("""
    <div class="disclaimer">
        ⚠️ <strong>Only scan domains you own or have explicit permission to test.</strong><br>
        This tool performs passive, non-intrusive checks only.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Input
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        domain_input = st.text_input(
            "Enter your domain",
            placeholder="example.com",
            label_visibility="collapsed"
        )
        scan_button = st.button("🔍 SCAN NOW", use_container_width=True)
    
    if scan_button and domain_input:
        domain = clean_domain(domain_input)
        
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$', domain):
            st.error("Please enter a valid domain (e.g., example.com)")
            return
        
        with st.spinner(f"Scanning {domain}..."):
            progress = st.progress(0)
            progress.progress(25, "Checking TLS/SSL...")
            result = run_scan(domain)
            progress.progress(100, "Complete!")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Results Header
        st.markdown(f"## Results for `{result.domain}`")
        st.markdown(f"*Scanned in {result.scan_time:.1f}s*")
        
        # Score and Stats
        col1, col2 = st.columns([1, 2])
        
        with col1:
            render_score(result.score, result.grade)
        
        with col2:
            # Quick stats
            critical_count = len([f for f in result.findings if f.severity == 'critical'])
            high_count = len([f for f in result.findings if f.severity == 'high'])
            medium_count = len([f for f in result.findings if f.severity == 'medium'])
            low_count = len([f for f in result.findings if f.severity in ['low', 'info']])
            
            st.markdown(f"""
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-number" style="color: #ff4757;">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #ff6b35;">{high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #ffd93d;">{medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" style="color: #00ff88;">{low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # TLS Summary
            if result.tls_info['valid']:
                st.success(f"✅ TLS: {result.tls_info['version']} | Expires: {result.tls_info['expires']} | Issuer: {result.tls_info['issuer']}")
            else:
                st.error("❌ TLS: Not valid or not available")
        
        st.markdown("---")
        
        # Findings
        if result.findings:
            st.markdown("## 🔍 Findings & Fixes")
            
            # Time estimate
            total_fix_time = len([f for f in result.findings if f.severity in ['critical', 'high']]) * 15 + \
                           len([f for f in result.findings if f.severity == 'medium']) * 10 + \
                           len([f for f in result.findings if f.severity in ['low', 'info']]) * 5
            
            st.info(f"⏱️ **Estimated fix time: {total_fix_time} minutes** — Start with Critical/High items first.")
            
            for finding in result.findings:
                render_finding(finding)
        else:
            st.success("🎉 No security issues found! Your domain looks secure.")
        
        # DNS Info
        st.markdown("---")
        st.markdown("## 📧 Email Security (DNS)")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**SPF Record:**")
            st.code(result.dns_info['spf'] or "Not found", language=None)
        with col2:
            st.markdown("**DMARC Record:**")
            st.code(result.dns_info['dmarc'] or "Not found", language=None)
        
        # Export option
        st.markdown("---")
        report_text = f"""
ShipSecure Security Report
==========================
Domain: {result.domain}
Score: {result.score}/100 (Grade: {result.grade})
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

FINDINGS ({len(result.findings)} total):
"""
        for f in result.findings:
            report_text += f"\n[{f.severity.upper()}] {f.title}\n  → {f.description}\n  Fix: {f.fix}\n"
        
        st.download_button(
            label="📥 Download Report",
            data=report_text,
            file_name=f"shipsecure-{domain}-report.txt",
            mime="text/plain"
        )


if __name__ == "__main__":
    main()
