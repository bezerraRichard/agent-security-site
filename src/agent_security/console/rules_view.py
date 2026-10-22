"""Catalogue of rules and how each one maps to Bitsight."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agent_security.console import theme
from agent_security.console.data import SECTION_LABELS
from agent_security.taxonomy import BITSIGHT, RULE_INFO, WAH, WAS, section_of

BITSIGHT_SOURCES = (
    ("Web Application Security Risk Vector", "https://help.bitsighttech.com/hc/en-us/articles/16080366996119"),
    (
        "Ratings Algorithm Update: Web Application Risk Vectors",
        "https://help.bitsighttech.com/hc/en-us/articles/29719454397079",
    ),
    (
        "Web Application Security Assessment: Sensitive Data Exposure",
        "https://help.bitsighttech.com/hc/en-us/articles/16118459570327",
    ),
)


def render() -> None:
    theme.page_header("Rules and BitSight", "What is checked and how it relates to BitSight.", eyebrow="Methodology")
    theme.note(
        "Since 10 July 2025 the BitSight rating uses the Web Application Security (WAS) risk vector, which replaced "
        "Web Application Headers (WAH). The mapping below is approximate and based on public BitSight documentation; "
        "BitSight loads the home page of each domain in a browser and does not crawl the site."
    )
    st.markdown("&nbsp;")
    rows = []
    for rule, (description, references) in RULE_INFO.items():
        vector, category, assessment = BITSIGHT.get(rule, (None, "Not assessed by Bitsight", None))
        rows.append(
            {
                "Rule": rule,
                "Section": SECTION_LABELS.get(section_of(rule), section_of(rule)),
                "BitSight vector": {WAS: "WAS", WAH: "WAH (legacy)"}.get(vector or "", "—"),
                "Category": category,
                "BitSight assessment": assessment or "—",
                "Description": description,
                "Reference": references[0] if references else None,
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        height=36 * (len(rows) + 1) + 4,
        column_config={"Reference": st.column_config.LinkColumn(display_text="open")},
    )
    st.markdown("##### BitSight sources")
    st.markdown("\n".join(f"- [{title}]({url})" for title, url in BITSIGHT_SOURCES))
    st.markdown("##### Limitations")
    st.markdown(
        "- Static HTML only: pages built by JavaScript, forms and authenticated areas are not covered.\n"
        "- TLS protocols and ciphers (BitSight SSL/TLS vectors) and vulnerable JavaScript libraries are not assessed.\n"
        "- Cookie values are never stored; only cookie names are sent to OneTrust."
    )
