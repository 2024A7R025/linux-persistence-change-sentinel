
import json
from pathlib import Path

import streamlit as st

st.set_page_config(
    page_title="Linux Persistence Change Sentinel",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Linux Persistence Change Sentinel")
st.caption("Linux persistence monitoring — demonstration dashboard")

root = Path(__file__).parent
events_file = root / "dashboard" / "events.json"
baseline_file = root / "baseline.json"

st.info(
    "Demo mode: this hosted dashboard displays saved project data. "
    "It does not monitor your personal Linux machine in real time."
)

def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default

events_data = load_json(events_file, {"events": []})
baseline_data = load_json(baseline_file, {"items": {}})

events = events_data.get("events", [])
items = baseline_data.get("items", {})

col1, col2, col3 = st.columns(3)
col1.metric("Detected Events", len(events))
col2.metric("Baseline Items", len(items))
col3.metric("Status", "Changes Detected" if events else "Healthy")

st.subheader("Detected Events")
if events:
    st.json(events)
else:
    st.success("No events are present in the saved demo data.")

st.subheader("Baseline Summary")
if items:
    st.json(items)
else:
    st.write("No baseline file or baseline items found.")

