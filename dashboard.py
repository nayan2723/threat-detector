import streamlit as st
import pandas as pd
import json
from pathlib import Path
import plotly.express as px

# Configure page
st.set_page_config(page_title="Windows Threat Dashboard", layout="wide")

# Custom CSS for a sleek look
st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    h1 {
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    </style>
""",
    unsafe_allow_html=True,
)

st.title("Windows Threat Detection Dashboard")
st.markdown("Visualize security alerts generated from EVTX log analysis.")


@st.cache_data
def load_data():
    alerts_path = Path("output/alerts.json")
    if not alerts_path.exists():
        return pd.DataFrame()
    with open(alerts_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data:
        return pd.DataFrame()

    # Flatten the mitre dictionary
    df = pd.json_normalize(data)
    # Convert timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    elif "time_window_start" in df.columns:
        df["timestamp"] = pd.to_datetime(df["time_window_start"])

    return df


df = load_data()

if df.empty:
    st.warning(
        "No alerts found. Run the detection engine first to generate `output/alerts.json`."
    )
else:
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(df))
    col2.metric("Critical Alerts", len(df[df["severity"] == "CRITICAL"]))
    col3.metric("High Alerts", len(df[df["severity"] == "HIGH"]))
    col4.metric(
        "Unique Mitre Tactics",
        df["mitre.tactic"].nunique() if "mitre.tactic" in df.columns else 0,
    )

    st.markdown("---")

    # Layout
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Alerts by Severity")
        # Define modern color map
        color_map = {
            "CRITICAL": "#FF4B4B",
            "HIGH": "#FFA62B",
            "MEDIUM": "#FFD166",
            "LOW": "#06D6A0",
        }
        fig1 = px.pie(
            df,
            names="severity",
            color="severity",
            color_discrete_map=color_map,
            hole=0.5,
        )
        fig1.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=20, b=20, l=20, r=20),
            showlegend=True,
        )
        st.plotly_chart(fig1, use_container_width=True)

    with c2:
        st.subheader("Top MITRE Techniques")
        if "mitre.technique_name" in df.columns:
            tech_counts = df["mitre.technique_name"].value_counts().reset_index()
            tech_counts.columns = ['Technique', 'Count']
            tech_counts = tech_counts.sort_values(by="Count", ascending=True)
            fig2 = px.bar(
                tech_counts,
                x="Count",
                y="Technique",
                orientation="h",
                color="Count",
                color_continuous_scale="Blues",
            )
            fig2.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=20, b=20, l=20, r=20),
                xaxis=dict(showgrid=False, title=""),
                yaxis=dict(showgrid=False, title=""),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No MITRE techniques mapped in the alerts.")

    st.markdown("---")
    st.subheader("Recent Alerts")

    # Filter and display dataframe
    columns_to_show = ["timestamp", "severity", "detection", "computer"]
    if "mitre.technique_id" in df.columns:
        columns_to_show.append("mitre.technique_id")

    # Ensure columns exist
    columns_to_show = [c for c in columns_to_show if c in df.columns]

    display_df = df[columns_to_show].sort_values(by="timestamp", ascending=False)
    st.dataframe(display_df, use_container_width=True)
