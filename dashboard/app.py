"""Shadow Agent Detection dashboard.

Reads ../findings.json (relative to this file) unless FINDINGS_PATH is set.
Run with: streamlit run dashboard/app.py
"""
import json
import os
from pathlib import Path

import streamlit as st

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "findings.json"
FINDINGS_PATH = Path(os.environ.get("FINDINGS_PATH", DEFAULT_PATH))


def load_findings():
    if not FINDINGS_PATH.exists():
        return None, []
    with open(FINDINGS_PATH) as f:
        data = json.load(f)
    return data.get("generated_at"), data.get("findings", [])


st.title("Shadow Agent Detection")
generated_at, findings = load_findings()

if findings is None:
    st.warning("No findings yet. Run correlator/correlate.py first.")
    st.stop()

st.caption(f"Last scan: {generated_at or 'unknown'}")

registered = sum(1 for x in findings if x.get("status") == "registered")
shadow = sum(1 for x in findings if x.get("status") == "shadow-candidate")
c1, c2, c3 = st.columns(3)
c1.metric("Workloads observed", len(findings))
c2.metric("Registered", registered)
c3.metric("Shadow candidates", shadow)

if not findings:
    st.info("No workloads observed in the last scan window.")
    st.stop()

for f in findings:
    is_shadow = f.get("status") == "shadow-candidate"
    badge = ":red[SHADOW CANDIDATE]" if is_shadow else ":green[REGISTERED]"
    with st.expander(
        f"{badge}  {f.get('instance_name', 'unknown')} ({f.get('instance_id', '?')})",
        expanded=is_shadow,
    ):
        st.write(badge)
        st.write(
            f"**Workload:** {f.get('instance_name', '?')} ({f.get('instance_id', '?')})  "
            f"**AI destination:** {f.get('ai_destination', '?')}  "
            f"**Owner:** {f.get('owner', '?')}  "
            f"**IAM role:** {f.get('iam_role', '?')}  "
            f"**Confidence:** {f.get('confidence', '?')}"
        )
        ev = f.get("evidence") or []
        if ev:
            st.markdown("**Evidence:**")
            for e in ev:
                st.markdown(f"- {e}")
        actions = f.get("downstream_actions") or []
        if actions:
            st.markdown("**Downstream actions:**")
            st.table(
                [
                    {
                        "time": a.get("time"),
                        "event": a.get("event"),
                        "detail": a.get("detail"),
                    }
                    for a in actions
                ]
            )
