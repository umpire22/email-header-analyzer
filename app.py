
import streamlit as st
import re

def analyze_header(header_text):
    red_flags = []

    # Check From vs Return-Path mismatch (compare only the email addresses)
    from_match = re.search(r'From:\s*(.*)', header_text, re.IGNORECASE)
    return_path_match = re.search(r'Return-Path:\s*<(.*)>', header_text, re.IGNORECASE)
    if from_match and return_path_match:
        from_email = re.search(r'[\w\.-]+@[\w\.-]+', from_match.group(1))
        return_email = re.search(r'[\w\.-]+@[\w\.-]+', return_path_match.group(1))
        if from_email and return_email and from_email.group(0).lower() != return_email.group(0).lower():
            red_flags.append("❗ Mismatch between From and Return-Path")

    # Extract IPs from Received headers
    received_ips = re.findall(r'Received:.*\[(\d{1,3}(?:\.\d{1,3}){3})\]', header_text)
    for ip in received_ips:
        # Known private IP ranges only
        private_ip_prefixes = [
            "10.",
            "192.168.",
        ] + [f"172.{i}." for i in range(16, 32)]

        if any(ip.startswith(prefix) for prefix in private_ip_prefixes):
            red_flags.append(f"⚠️ Internal/private IP found: {ip}")

    # SPF check
    if re.search(r'spf\s*=\s*(fail|softfail)', header_text, re.IGNORECASE):
        red_flags.append("❗ SPF check failed — possible spoofing")

    # DKIM check
    if re.search(r'dkim\s*=\s*fail', header_text, re.IGNORECASE):
        red_flags.append("❗ DKIM failed")

    # DMARC check
    if re.search(r'dmarc\s*=\s*fail', header_text, re.IGNORECASE):
        red_flags.append("❗ DMARC failed")

    # Final verdict
    result = "⛔ Email flagged as Suspicious or Malicious" if red_flags else "✅ Email appears Safe"
    return result, red_flags


# ---------------- Streamlit UI ---------------- #
st.set_page_config(page_title="Email Header Analyzer", layout="centered")
st.title("📧 Email Header Analyzer AI")
st.markdown("Paste the full **raw email header** below. Click 'Analyze' to check if it's suspicious.")

# Manual paste input
header_input = st.text_area("🔻 Paste Email Header Here:", height=300)

# Analyze button
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
