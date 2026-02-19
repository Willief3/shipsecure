# 🛡️ ShipSecure

**Instant security assessment for startups that ship fast.**

A free, open-source security scanner that gives founders a quick health check before vulnerabilities cost them customers, reputation, or AWS keys.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-FF4B4B)

## 🎯 Why ShipSecure?

AI/biotech startups ship fast. Security gets deprioritized. Existing tools (Nmap, Nuclei, Burp) are built for security engineers, not founders checking their landing page before launch.

**ShipSecure bridges the gap:** enter your domain → get a risk score → get actionable fixes with time estimates.

## ✨ What It Checks

| Category | Checks | Why It Matters |
|----------|--------|----------------|
| **TLS/SSL** | Certificate validity, expiry, TLS version | Expired certs = browser warnings = lost trust |
| **Security Headers** | HSTS, CSP, X-Frame-Options, etc. | Missing headers = XSS, clickjacking, MITM risks |
| **Email Security** | SPF, DMARC, DKIM | Missing = anyone can spoof emails from your domain |

### 🛡️ Security Philosophy

This tool performs **passive, non-intrusive checks only**:
- No port scanning
- No active exploitation attempts
- No credential brute-forcing
- Only checks publicly available information

**Important:** Only scan domains you own or have explicit permission to test.

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/yourusername/shipsecure.git
cd shipsecure

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

## 📊 Understanding Your Score

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Solid security posture |
| 80-89 | B | Good, minor improvements needed |
| 70-79 | C | Needs attention, several gaps |
| 60-69 | D | At risk, prioritize fixes |
| 0-59 | F | Critical issues, fix immediately |

## 🔧 Severity Levels

- **🔴 Critical**: Fix now. Active security risk.
- **🟠 High**: Fix this week. Significant exposure.
- **🟡 Medium**: Fix this month. Best practice gaps.
- **🟢 Low/Info**: Nice to have. Minor improvements.

## 🗺️ Roadmap

### v1.1
- [ ] PDF report export
- [ ] Subdomain discovery (passive DNS)
- [ ] Technology fingerprinting
- [ ] Historical scan comparison

### v1.2
- [ ] API endpoint for CI/CD integration
- [ ] Slack/Discord notifications
- [ ] Custom severity thresholds

### v2.0
- [ ] User accounts & saved scans
- [ ] Scheduled monitoring
- [ ] Team dashboards

## 🤝 Contributing

PRs welcome! Areas where help is needed:
- Additional security checks
- UI/UX improvements
- Documentation & tutorials
- Translations

## ⚖️ License

MIT License - Use freely, build on it, share the knowledge.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have permission to scan any domain. The authors are not responsible for misuse.

## 🙏 Acknowledgments

Built with insights from:
- OWASP Security Headers Project
- Mozilla Observatory methodology
- HackTheBox recon techniques

---

**Made for founders who ship fast and want to ship secure.** 🚀
