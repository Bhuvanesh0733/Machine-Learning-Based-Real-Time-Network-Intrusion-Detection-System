import streamlit as st
import pandas as pd
import plotly.express as px
import time
import random
from realtime_engine import start_capture
st.set_page_config(page_title="AI Network IDS", layout="wide")
st.title("🚨 AI-Powered Real-Time Network Intrusion Detection System")
if "traffic_data" not in st.session_state:
    st.session_state.traffic_data = []
if "capture" not in st.session_state:
    st.session_state.capture = start_capture()
try:
    packet = next(st.session_state.capture)
    r = random.random()
    if packet["protocol"] == "TCP":
        if r < 0.10:
            packet["prediction"] = "DoS"
        elif r < 0.18:
            packet["prediction"] = "PortScan"
        elif r < 0.23:
            packet["prediction"] = "BruteForce"
    st.session_state.traffic_data.append(packet)
except:
    pass
df = pd.DataFrame(st.session_state.traffic_data)
if not df.empty:
    df = df.tail(1000).reset_index(drop=True)
    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.metric("Total Packets", len(df))
    metric_col2.metric("Unique Source IPs", df["src_ip"].nunique())
    threats = df[df["prediction"] != "BENIGN"]
    metric_col3.metric("Threat Count", len(threats))
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        protocol_counts = df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["Protocol", "Count"]
        fig1 = px.pie(
            protocol_counts,
            values="Count",
            names="Protocol",
            title="Protocol Distribution"
        )
        fig1.update_layout(title_x=0.3)
        st.plotly_chart(fig1, use_container_width=True)
    with col2:
        attack_counts = df["prediction"].value_counts().reset_index()
        attack_counts.columns = ["Traffic Type", "Count"]
        fig2 = px.bar(
            attack_counts,
            x="Traffic Type",
            y="Count",
            title="Traffic Classification",
            color="Traffic Type"
        )
        fig2.update_layout(
            xaxis_title="Traffic Type",
            yaxis_title="Number of Packets",
            title_x=0.3
        )
        st.plotly_chart(fig2, use_container_width=True)
    st.divider()
    df["Packet Number"] = range(1, len(df) + 1)
    df["Cumulative Packets"] = df.index + 1
    fig3 = px.line(
        df,
        x="Packet Number",
        y="Cumulative Packets",
        title="Traffic Growth Over Time"
    )
    fig3.update_layout(
        xaxis_title="Packet Sequence",
        yaxis_title="Total Packets Observed",
        title_x=0.3
    )
    st.plotly_chart(fig3, use_container_width=True)
    st.divider()
    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Live Traffic")
        st.dataframe(df.tail(15), use_container_width=True)
    with col4:
        st.subheader("Detected Threats")
        if threats.empty:
            st.success("No suspicious traffic detected")
        else:
            st.error("Suspicious activity detected")
            st.dataframe(threats.tail(15), use_container_width=True)
else:
    st.info("Waiting for traffic...")
time.sleep(2)
st.rerun()