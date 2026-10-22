"""New scan page: domains, limits, network, OneTrust and live progress."""

from __future__ import annotations

import os

import streamlit as st

from agent_security.config import HARD_MAX_PAGES, MIN_DELAY_SECONDS
from agent_security.console import state, theme
from agent_security.console.forms import PROFILES, ScanOptions, build_configs, parse_domain_lines, split_hosts
from agent_security.console.jobs import ScanJob

STATE_LABELS = {
    "queued": ("Em espera", "neutral"),
    "running": ("A analisar", "warn"),
    "done": ("Concluído", "ok"),
    "failed": ("Falhou", "bad"),
    "cancelled": ("Cancelado", "neutral"),
}
ROUTES = {
    "auto": "Automático (proxy do sistema, depois direto)",
    "proxy": "Proxy explícito",
    "direct": "Ligação direta",
}


def _limits() -> tuple[int, int, float, float]:
    profile = st.segmented_control(
        "Perfil de varredura", [*PROFILES, "Personalizado"], default="Conservador", key="profile"
    )
    if profile in PROFILES:
        pages, depth, delay, minutes = PROFILES[profile]
        st.caption(
            f"Até {pages} páginas por domínio · profundidade {depth} · {delay:g} s entre pedidos · {minutes:g} min"
        )
        return pages, depth, delay, minutes
    columns = st.columns(4)
    pages = columns[0].number_input("Máx. páginas", 1, HARD_MAX_PAGES, 100, step=50)
    depth = columns[1].number_input("Profundidade", 0, 50, 3)
    delay = columns[2].number_input("Pausa (s)", MIN_DELAY_SECONDS, 30.0, 1.0, step=0.1, format="%.1f")
    minutes = columns[3].number_input("Limite (min)", 1.0, 600.0, 20.0, step=5.0)
    return int(pages), int(depth), float(delay), float(minutes)


def _form() -> None:
    with st.container(border=True):
        st.markdown("##### Domínios")
        text = st.text_area(
            "Domínios",
            key="domains",
            height=130,
            placeholder="www.example.com\nwww.example.org  shop.example.org  cdn.example.org",
            label_visibility="collapsed",
        )
        st.caption(
            "Um domínio por linha; outros hostnames autorizados para esse domínio podem seguir na mesma linha. "
            "Cada domínio é analisado em separado e tem o seu próprio relatório."
        )
        rows = parse_domain_lines(text)
        if rows:
            # st.html, not st.markdown: markdown would turn the hostnames into links.
            st.html(
                " ".join(
                    theme.pill(domain + (f" + {len(split_hosts(extra))} hosts" if extra else ""), "neutral")
                    for domain, extra in rows
                )
            )

    with st.container(border=True):
        st.markdown("##### Limites")
        pages, depth, delay, minutes = _limits()
        left, right = st.columns(2)
        sitemap = left.toggle("Usar sitemap.xml como ponto de partida", value=False)
        robots = right.toggle("Respeitar robots.txt", value=True)
        if not robots:
            theme.note("Ignorar o robots.txt só com instrução explícita do responsável pelo site.", warn=True)

    with st.expander("Rede"):
        route = st.radio("Rota", list(ROUTES), format_func=lambda route: ROUTES[route], horizontal=True)
        proxy, fallback = "", False
        if route == "proxy":
            proxy = st.text_input("URL do proxy", placeholder="http://proxy.example:8080")
            fallback = st.checkbox("Se o proxy falhar, tentar ligação direta")
        ca_bundle = st.text_input(
            "Ficheiro PEM com CAs adicionais (opcional)", help="Ex.: CA de inspeção TLS corporativa"
        )

    onetrust = state.onetrust_status()
    with st.container(border=True):
        st.markdown("##### Classificação de cookies (OneTrust)")
        if onetrust["configured"]:
            st.markdown(
                theme.pill("Configurada", "ok")
                + f"&nbsp; <span class='domain-progress'>{theme.esc(onetrust['hostname'])}"
                f" · idioma {theme.esc(onetrust['language'])}</span>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(theme.pill(onetrust["detail"], "neutral"), unsafe_allow_html=True)
            st.caption(
                "Defina ONETRUST_HOSTNAME, ONETRUST_CLIENT_ID e ONETRUST_CLIENT_SECRET antes de abrir a consola."
            )
        classify = st.toggle("Classificar cookies", value=onetrust["configured"], disabled=not onetrust["configured"])
        language, domain_ids = "", ""
        if onetrust["configured"] and classify:
            left, right = st.columns([1, 3])
            language = left.text_input("Idioma", placeholder=onetrust["language"])
            domain_ids = right.text_input("IDs de domínio OneTrust (opcional)", help="UUIDs separados por vírgulas")
        st.caption("Só os nomes dos cookies são enviados ao seu tenant OneTrust; os valores nunca são guardados.")

    authorized = st.checkbox(
        "Confirmo que tenho autorização escrita para avaliar todos os domínios e hosts indicados.", key="authorized"
    )
    registry = state.registry()
    busy = bool(registry.current and registry.current.running)
    has_domains = bool(rows)
    if st.button(
        "Iniciar análise",
        type="primary",
        width="stretch",
        disabled=busy or not authorized or not has_domains,
        help="Já existe uma análise em curso." if busy else None,
    ):
        options = ScanOptions(
            max_pages=pages,
            max_depth=depth,
            delay_seconds=delay,
            time_limit_minutes=minutes,
            respect_robots=robots,
            sitemap=sitemap,
            route=route or "auto",
            proxy=proxy,
            fallback_direct=fallback,
            ca_bundle=ca_bundle,
            classify_cookies=classify,
            onetrust_language=language.strip(),
            onetrust_domain_ids=tuple(split_hosts(domain_ids)),
        )
        try:
            configs = build_configs(rows, options, os.environ)
            job = registry.start(configs, state.reports_dir())
        except (ValueError, RuntimeError) as error:
            st.error(str(error))
        else:
            state.select_batch(job.id)
            st.rerun()


def _job_body(job: ScanJob) -> None:
    done = sum(d.state in {"done", "failed", "cancelled"} for d in job.domains)
    headline = "Em curso" if job.running else ("Cancelada" if job.cancel_requested else "Concluída")
    tone = "warn" if job.running else ("neutral" if job.cancel_requested else "ok")
    st.markdown(
        f"{theme.pill(headline, tone)} &nbsp;<span class='domain-progress'>Lote {theme.esc(job.id)} · "
        f"{done}/{len(job.domains)} domínios</span>",
        unsafe_allow_html=True,
    )
    for domain in job.domains:
        label, tone = STATE_LABELS[domain.state]
        with st.container(border=True):
            st.html(f"<b>{theme.esc(domain.target)}</b> &nbsp; {theme.pill(label, tone)}")
            if domain.state == "running":
                st.progress(
                    min(domain.pages / max(domain.max_pages, 1), 1.0), text=f"{domain.pages}/{domain.max_pages} páginas"
                )
                st.markdown(f"<div class='domain-progress'>{theme.esc(domain.last_url)}</div>", unsafe_allow_html=True)
            elif domain.state in {"done", "cancelled"} and domain.status:
                st.markdown(
                    f"<div class='domain-progress'>{domain.pages} páginas · {domain.findings} problemas distintos · "
                    f"{theme.esc(domain.status)}</div>",
                    unsafe_allow_html=True,
                )
            elif domain.state == "failed":
                st.error(domain.error or "Erro desconhecido")
    if job.error:
        st.error(job.error)
    if job.running:
        if st.button("Cancelar análise", disabled=job.cancel_requested, width="stretch"):
            job.cancel()
    elif st.button("Ver painel do lote", type="primary", width="stretch"):
        state.select_batch(job.id)
        st.switch_page(st.session_state["pages"]["dashboard"])


@st.fragment(run_every=1.0)
def _live_job(job: ScanJob) -> None:
    if not job.running:
        st.rerun()  # Re-render the whole page so the finished batch shows up everywhere.
    _job_body(job)


def render() -> None:
    theme.page_header(
        "Nova análise",
        "Varredura passiva de cabeçalhos, CSP, cookies e conteúdo, com alinhamento BitSight e classificação OneTrust.",
        eyebrow="Análise",
    )
    form, progress = st.columns([3, 2], gap="large")
    with form:
        _form()
    with progress:
        st.markdown("##### Progresso")
        job = state.registry().current
        if job is None:
            theme.note("Nenhuma análise iniciada nesta sessão da consola.")
        elif job.running:
            _live_job(job)
        else:
            _job_body(job)
        st.markdown("&nbsp;")
        theme.note(
            "Só pedidos GET, um de cada vez, com pausa entre pedidos. Não há autenticação, formulários nem payloads "
            "de ataque, e os redirecionamentos para fora dos hosts autorizados não são seguidos."
        )
