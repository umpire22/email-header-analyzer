import streamlit as st
import re

def analyze_header(header_text):
    red_flags = []

    from_match = re.search(r'From:\s*(.*)', header_text, re.IGNORECASE)
    return_path_match = re.search(r'Return-Path:\s*<(.*)>', header_text, re.IGNORECASE)
    if from_match and return_path_match:
        if from_match.group(1).strip() != return_path_match.group(1).strip():
            red_flags.append("❗ Mismatch between From and Return-Path")

    received_ips = re.findall(r'Received:.*\[(\d{1,3}(?:\.\d{1,3}){3})\]', header_text)
    for ip in received_ips:
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            red_flags.append(f"⚠️ Internal/private IP found: {ip}")

    if "spf=fail" in header_text.lower() or "spf=softfail" in header_text.lower():
        red_flags.append("❗ SPF check failed — possible spoofing")
    if "dkim=fail" in header_text.lower():
        red_flags.append("❗ DKIM failed")
    if "dmarc=fail" in header_text.lower():
        red_flags.append("❗ DMARC failed")

    result = "⛔ Email flagged as Suspicious or Malicious" if red_flags else "✅ Email appears Safe"
    return result, red_flags


st.set_page_config(page_title="Email Header Analyzer", layout="centered")
st.title("📧 Email Header Analyzer AI")
st.markdown("Paste the full **raw email header** below. Click 'Analyze' to see if it's suspicious.")

header_input = st.text_area("🔻 Paste Email Header Here:", height=300)

if st.button("Analyze"):
    if header_input.strip():
        result, flags = analyze_header(header_input)
        st.subheader("🔍 Result")
        if "Safe" in result:
            st.success(result)
        else:
            st.error(result)
        for flag in flags:
            st.write("•", flag)
    else:
        st.warning("Please paste an email header to analyze.")
