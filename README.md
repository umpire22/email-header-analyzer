# 📧 Email Header Analyzer

A simple AI-powered tool built with **Python** and **Streamlit** to help users detect suspicious or potentially malicious email headers — useful for cybersecurity education, awareness, and basic analysis.

---

## 🚀 Live Demo

👉 [Click here to try the app on Streamlit](https://email-header-analyzer-xxxxxxxx.streamlit.app)

No installation needed — just paste an email header and get an instant risk assessment.

---

## 🔍 What It Does

- Extracts IP addresses from email headers
- Flags internal/private IPs
- Checks for suspicious keywords like `SPF=fail`, `DKIM=fail`, and `DMARC=fail`
- Gives a simple "Safe" or "Suspicious" verdict
- Useful for teaching basic email security concepts

---

## 📁 Project Structure

```bash
email-header-analyzer/
├── app.py                # Main Streamlit app
├── requirements.txt      # Required Python packages
└── README.md             # Project description (this file)
