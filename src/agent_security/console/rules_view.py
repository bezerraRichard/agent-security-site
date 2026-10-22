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
    theme.page_header(
        "Regras e BitSight", "O que é verificado e como se relaciona com a BitSight.", eyebrow="Metodologia"
    )
    theme.note(
        "O rating BitSight usa, desde 10/07/2025, o vetor Web Application Security (WAS), que substituiu o Web "
        "Application Headers (WAH). O mapeamento abaixo é aproximado e baseado na documentação pública da BitSight; "
        "a BitSight carrega a página inicial de cada domínio num browser e não percorre o site."
    )
    st.markdown("&nbsp;")
    rows = []
    for rule, (description, references) in RULE_INFO.items():
        vector, category, assessment = BITSIGHT.get(rule, (None, "Not assessed by Bitsight", None))
        rows.append(
            {
                "Regra": rule,
                "Secção": SECTION_LABELS.get(section_of(rule), section_of(rule)),
                "Vetor BitSight": {WAS: "WAS", WAH: "WAH (legado)"}.get(vector or "", "—"),
                "Categoria": category,
                "Avaliação BitSight": assessment or "—",
                "Descrição": description,
                "Referência": references[0] if references else None,
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        height=36 * (len(rows) + 1) + 4,
        column_config={"Referência": st.column_config.LinkColumn(display_text="abrir")},
    )
    st.markdown("##### Fontes BitSight")
    st.markdown("\n".join(f"- [{title}]({url})" for title, url in BITSIGHT_SOURCES))
    st.markdown("##### Limitações")
    st.markdown(
        "- Só HTML estático: páginas geradas por JavaScript, formulários e áreas autenticadas não são cobertos.\n"
        "- Não avalia protocolos nem cifras TLS (vetores BitSight SSL/TLS) nem bibliotecas JavaScript vulneráveis.\n"
        "- Os valores dos cookies nunca são guardados; só os nomes vão para a OneTrust."
    )
