import streamlit as st
import re

st.set_page_config(
    page_title="Threat Intelligence Aggregator",
    page_icon="🛡️"
)

st.title("🛡️ Threat Intelligence Aggregator")
st.write("Threat Intelligence Analysis Web Demonstration")

st.divider()

st.subheader("IOC Analyzer")

ioc = st.text_input(
    "Enter an IOC",
    placeholder="Example: 45.33.32.156"
)

def detect_type(value):
    value = value.strip()

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"

    if re.match(ip_pattern, value):
        return "IP Address"

    if value.startswith("http://") or value.startswith("https://"):
        return "URL"

    if re.match(hash_pattern, value):
        return "Hash"

    if "." in value:
        return "Domain"

    return "Unknown"


def classify_risk(ioc_type):
    if ioc_type in ["IP Address", "URL", "Hash"]:
        return "HIGH"

    if ioc_type == "Domain":
        return "MEDIUM"

    return "LOW"


if st.button("Analyze IOC"):

    if not ioc.strip():
        st.warning("Please enter an IOC.")

    else:
        ioc_type = detect_type(ioc)
        risk = classify_risk(ioc_type)

        st.subheader("Analysis Result")

        st.write(f"**IOC:** {ioc}")
        st.write(f"**Type:** {ioc_type}")
        st.write(f"**Risk Level:** {risk}")

        if risk == "HIGH":
            st.error("⚠️ HIGH-RISK IOC detected")

        elif risk == "MEDIUM":
            st.warning("⚠️ MEDIUM-RISK IOC detected")

        else:
            st.success("LOW-RISK IOC")

st.divider()

st.subheader("Project Information")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Stored IOCs", "16")

with col2:
    st.metric("High Risk IOCs", "12")

with col3:
    st.metric("Medium Risk IOCs", "4")

st.info(
    "This web demonstration presents the IOC analysis functionality "
    "of the Threat Intelligence Aggregator project."
)

st.caption(
    "Full project implementation is available in the GitHub repository."
)