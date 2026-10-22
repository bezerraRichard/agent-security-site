"""Action plan: turn the findings of one or more reports into prioritised, owner-specific remediation steps."""

from __future__ import annotations

import json
import math
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_security.fingerprint import AEM, AEM_CLOUD
from agent_security.taxonomy import SEVERITY_ORDER, bitsight_of

SEVERITY_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Info": 5}
PRIORITY_THRESHOLDS = (("P1", 90), ("P2", 60), ("P3", 30))
STATUSES = ("Por fazer", "Em curso", "Feito", "Risco aceite")
# Cookies written by the OneTrust banner script: they must stay readable by JavaScript.
ONETRUST_COOKIES = ("OptanonConsent", "OptanonAlertBoxClosed", "eupubconsent", "OTAdditionalConsentString")
NECESSARY_HINTS = ("necess", "essential", "essencia", "strictly", "estritamente")
ONETRUST_UPDATE_COOKIE = "PUT /api/cookiemanager/v1/cookies"


@dataclass
class Action:
    key: str
    title: str
    severity: str
    owner: str
    effort: str
    why: str
    steps: list[str]
    verify: str
    snippet: str = ""
    snippet_language: str = "text"
    bitsight: str | None = None
    rules: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    pages: int = 0

    @property
    def score(self) -> float:
        score: float = SEVERITY_WEIGHT.get(self.severity, 0) + (15 if self.bitsight else 0)
        score += min(15.0, 5 * math.log10(self.pages + 1)) + 5 * max(len(self.domains) - 1, 0)
        return round(score, 1)

    @property
    def priority(self) -> str:
        return next((name for name, minimum in PRIORITY_THRESHOLDS if self.score >= minimum), "P4")


@dataclass(frozen=True)
class Platform:
    cdn: str | None = None
    cms: str | None = None
    technologies: tuple[str, ...] = ()

    @property
    def aem_cloud(self) -> bool:
        return self.cms == AEM_CLOUD

    @property
    def aem(self) -> bool:
        return self.cms in {AEM, AEM_CLOUD}

    def header_owner(self) -> str:
        if self.aem_cloud:
            return "Adobe AEM · CDN (cdn.yaml, Config Pipeline)"
        if self.aem:
            return "Adobe AEM · Dispatcher (vhost)"
        return f"CDN {self.cdn}" if self.cdn else "Servidor web / reverse proxy"


def platform_of(report: dict[str, Any]) -> Platform:
    info = report.get("platform") or {}
    return Platform(info.get("cdn"), info.get("cms"), tuple(info.get("technologies") or ()))


def _yaml(value: str) -> str:
    """A JSON string is a valid double-quoted YAML scalar, which keeps CSP quotes and backslashes intact."""
    return json.dumps(value)


def header_snippet(platform: Platform, header: str, value: str) -> tuple[str, str]:
    """(snippet, language) that sets a response header on the detected platform."""
    if platform.aem_cloud:
        return (
            "# config/cdn.yaml — deploy through a Cloud Manager Config Pipeline\n"
            'kind: "CDN"\nversion: "1"\ndata:\n  responseTransformations:\n    rules:\n'
            f"      - name: set-{header.lower()}\n        when:\n          reqProperty: path\n          like: '*'\n"
            f"        actions:\n          - type: set\n            respHeader: {header}\n"
            f"            value: {_yaml(value)}\n",
            "yaml",
        )
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'# Apache / AEM Dispatcher vhost (mod_headers)\nHeader always set {header} "{escaped}"\n', "apacheconf"


def _curl(domain: str, header: str) -> str:
    return f'curl -sI https://{domain}/ | grep -i "^{header.lower()}"'


@dataclass(frozen=True)
class Playbook:
    title: str
    effort: str
    why: str
    steps: Callable[[Platform, dict[str, Any]], list[str]]
    header: str | None = None
    value: str | None = None
    owner: Callable[[Platform, dict[str, Any]], str] | None = None
    snippet: Callable[[Platform, dict[str, Any]], tuple[str, str]] | None = None
    verify: Callable[[str, dict[str, Any]], str] | None = None


def _header_steps(header: str, value: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    def steps(platform: Platform, group: dict[str, Any]) -> list[str]:
        if platform.aem_cloud:
            return [
                f"Acrescentar a regra que define `{header}: {value}` ao `cdn.yaml` do repositório AEM "
                "(pasta `config/`).",
                "Fazer deploy em dev e stage com o Config Pipeline do Cloud Manager e validar o site.",
                "Promover para produção e confirmar o cabeçalho com o comando de verificação.",
            ]
        if platform.aem:
            return [
                f"Acrescentar `Header always set {header}` ao vhost do Dispatcher.",
                "Validar em stage, publicar e invalidar a cache.",
            ]
        return [f"Configurar `{header}: {value}` na camada mais externa (CDN ou reverse proxy)."]

    return steps


def _code_steps(*lines: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    return lambda platform, group: list(lines)


def _frontend_owner(platform: Platform, group: dict[str, Any]) -> str:
    return "Front-end AEM e gestão de tags" if platform.aem else "Equipa de front-end e gestão de tags"


def _content_owner(platform: Platform, group: dict[str, Any]) -> str:
    return "Autores e front-end AEM" if platform.aem else "Equipa de front-end"


def _cookie_owner(platform: Platform, group: dict[str, Any]) -> str:
    name = group.get("cookie") or ""
    if name.startswith(ONETRUST_COOKIES):
        return "OneTrust · script de consentimento"
    if name == "affinity" and platform.aem_cloud:
        return "Adobe AEM · cookie de afinidade da plataforma"
    return "Aplicação que define o cookie"


def _cookie_steps(attribute: str) -> Callable[[Platform, dict[str, Any]], list[str]]:
    def steps(platform: Platform, group: dict[str, Any]) -> list[str]:
        name = group.get("cookie") or "o cookie"
        if name.startswith(ONETRUST_COOKIES):
            return [
                f"O cookie `{name}` é escrito pelo script da OneTrust no browser.",
                "HttpOnly não se aplica a cookies que o JavaScript tem de ler; documentar como risco aceite.",
                "Confirmar no OneTrust (Cookie Consent > configuração do domínio) que Secure e SameSite estão ativos.",
            ]
        steps = [f"Identificar o componente que envia `Set-Cookie: {name}` (aplicação, dispatcher ou plataforma)."]
        if name == "affinity" and platform.aem_cloud:
            steps.append(
                "Em AEM as a Cloud Service este cookie é normalmente da camada de afinidade da Adobe; se não for "
                "definido pelo vosso código, abrir pedido no suporte Adobe para acrescentar o atributo."
            )
        steps.append(f"Acrescentar `{attribute}` ao cookie na origem e voltar a analisar.")
        return steps

    return steps


def _cookie_snippet(attribute: str) -> Callable[[Platform, dict[str, Any]], tuple[str, str]]:
    def snippet(platform: Platform, group: dict[str, Any]) -> tuple[str, str]:
        name = group.get("cookie") or "cookie"
        return (
            "# Apache / AEM Dispatcher vhost (mod_headers): acrescenta o atributo ao cookie\n"
            f'Header always edit Set-Cookie "^({name}=(?!.*{attribute.split("=")[0]}).*)$" "$1; {attribute}"\n',
            "apacheconf",
        )

    return snippet


def _cookie_verify(domain: str, group: dict[str, Any]) -> str:
    return f'curl -sI https://{domain}/ | grep -i "^set-cookie: {group.get("cookie") or ""}"'


def _header(rule_header: str, value: str, title: str, effort: str, why: str) -> Playbook:
    return Playbook(title, effort, why, _header_steps(rule_header, value), header=rule_header, value=value)


HSTS = "max-age=31536000; includeSubDomains"
PLAYBOOKS: dict[str, Playbook] = {
    "HDR-HSTS-001": _header(
        "Strict-Transport-Security", HSTS, "Ativar HSTS", "Baixo", "Impede ataques de downgrade para HTTP."
    ),
    "HDR-HSTS-002": _header(
        "Strict-Transport-Security", HSTS, "Aumentar o max-age do HSTS", "Baixo", "Um HSTS curto protege pouco."
    ),
    "HDR-HSTS-003": Playbook(
        "Preparar a inclusão na lista HSTS preload",
        "Médio",
        "Protege a primeira visita; é um controlo positivo na BitSight (WAS).",
        _code_steps(
            "Confirmar que todos os subdomínios servem HTTPS (a inclusão aplica-se a todos e é difícil de reverter).",
            "Acrescentar `preload` ao Strict-Transport-Security.",
            "Submeter o domínio em https://hstspreload.org/.",
        ),
        header="Strict-Transport-Security",
        value=HSTS + "; preload",
    ),
    "HDR-XCTO-001": _header(
        "X-Content-Type-Options", "nosniff", "Ativar X-Content-Type-Options", "Baixo", "Evita MIME-sniffing."
    ),
    "HDR-XFO-001": _header(
        "X-Frame-Options", "SAMEORIGIN", "Proteger contra clickjacking", "Baixo", "Impede que o site seja embutido."
    ),
    "HDR-REF-001": _header(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Definir Referrer-Policy",
        "Baixo",
        "Evita enviar URLs completos a terceiros.",
    ),
    "HDR-REF-002": _header(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
        "Corrigir a Referrer-Policy insegura",
        "Baixo",
        "A política atual envia URLs completos a outros sites.",
    ),
    "HDR-PP-001": _header(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
        "Definir Permissions-Policy",
        "Baixo",
        "Restringe funcionalidades do browser não usadas.",
    ),
    "CSP-000": Playbook(
        "Criar uma Content-Security-Policy",
        "Alto",
        "Sem CSP o browser não bloqueia scripts injetados.",
        _code_steps(
            "Inventariar as origens de scripts, estilos, imagens e frames usadas pelo site.",
            "Publicar a política como Content-Security-Policy-Report-Only e recolher violações.",
            "Quando as violações estiverem resolvidas, publicar como Content-Security-Policy.",
        ),
        header="Content-Security-Policy-Report-Only",
        value="default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; report-uri /csp-report",
    ),
    "CSP-001": Playbook(
        "Acrescentar default-src à CSP",
        "Médio",
        "Sem default-src, os tipos de recurso não listados ficam sem restrição.",
        _code_steps(
            "Confirmar quais cabeçalhos Content-Security-Policy são enviados (o browser aplica todos em conjunto).",
            "Acrescentar `default-src 'self'` à política e as origens necessárias às diretivas específicas.",
        ),
    ),
    "CSP-002": Playbook(
        "Remover 'unsafe-eval' da CSP",
        "Alto",
        "'unsafe-eval' permite executar código gerado dinamicamente e facilita XSS.",
        _code_steps(
            "Identificar o código que usa eval/new Function/setTimeout com strings (bibliotecas e tags de terceiros).",
            "Substituir ou atualizar esse código; retirar `'unsafe-eval'` primeiro numa política Report-Only.",
            "Publicar a política sem `'unsafe-eval'` quando não houver violações.",
        ),
        owner=_frontend_owner,
    ),
    "CSP-003": Playbook(
        "Substituir 'unsafe-inline' por nonces ou hashes",
        "Alto",
        "Scripts inline são o principal vetor de XSS.",
        _code_steps(
            "Mover scripts inline para ficheiros ou gerar um nonce por resposta e aplicá-lo às tags <script>.",
            "Acrescentar `'nonce-…'` (ou hashes) e `'strict-dynamic'` ao script-src.",
            "Retirar `'unsafe-inline'` depois de validar em Report-Only.",
        ),
        owner=_frontend_owner,
    ),
    "CSP-004": Playbook(
        "Passar a CSP Report-Only a obrigatória",
        "Médio",
        "Já existe uma política mais rígida em teste que ainda não protege os utilizadores.",
        _code_steps(
            "Rever as violações recolhidas pelo report-uri da política Report-Only.",
            "Corrigir as origens em falta e publicar a política como Content-Security-Policy.",
            "Retirar os cabeçalhos CSP antigos, para que a nova política não seja combinada com eles.",
        ),
    ),
    "COOKIE-SECURE": Playbook(
        "Acrescentar Secure ao cookie",
        "Baixo",
        "Sem Secure o cookie pode seguir por HTTP.",
        _cookie_steps("Secure"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("Secure"),
        verify=_cookie_verify,
    ),
    "COOKIE-HTTPONLY": Playbook(
        "Acrescentar HttpOnly ao cookie",
        "Baixo",
        "Sem HttpOnly o cookie fica acessível a scripts (risco XSS).",
        _cookie_steps("HttpOnly"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("HttpOnly"),
        verify=_cookie_verify,
    ),
    "COOKIE-SAMESITE": Playbook(
        "Acrescentar SameSite ao cookie",
        "Baixo",
        "SameSite=Lax ou Strict mitiga CSRF; é avaliado pela BitSight (WAS).",
        _cookie_steps("SameSite=Lax"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("SameSite=Lax"),
        verify=_cookie_verify,
    ),
    "COOKIE-SAMESITE-NONE": Playbook(
        "Corrigir SameSite=None sem Secure",
        "Baixo",
        "Os browsers rejeitam estes cookies; é avaliado pela BitSight (WAS).",
        _cookie_steps("Secure"),
        owner=_cookie_owner,
        snippet=_cookie_snippet("Secure"),
        verify=_cookie_verify,
    ),
    "MIXED-001": Playbook(
        "Eliminar conteúdo misto ativo",
        "Médio",
        "Scripts ou frames por HTTP podem ser alterados em trânsito.",
        _code_steps(
            "Substituir as referências http:// pelos equivalentes https:// (componentes, templates e conteúdo AEM).",
            "Como rede de segurança, acrescentar `upgrade-insecure-requests` à CSP.",
        ),
        owner=_content_owner,
    ),
    "MIXED-002": Playbook(
        "Eliminar conteúdo misto passivo",
        "Baixo",
        "Imagens por HTTP podem ser substituídas em trânsito.",
        _code_steps("Atualizar as referências http:// em imagens e media para https://."),
        owner=_content_owner,
    ),
    "SRI-001": Playbook(
        "Proteger scripts de terceiros",
        "Médio",
        "Sem integridade, um terceiro comprometido serve código malicioso ao site.",
        lambda platform, group: [
            "Acrescentar `integrity` e `crossorigin` aos ficheiros versionados de terceiros (bibliotecas fixas).",
            "Para recursos que mudam a cada publicação (gestores de tags"
            + (
                ", como o Adobe Experience Platform Tags"
                if "Adobe Experience Platform Tags" in platform.technologies
                else ""
            )
            + "), o SRI não funciona: restringir com a CSP.",
        ],
        owner=_frontend_owner,
    ),
    "URL-SESSION-001": Playbook(
        "Retirar identificadores de sessão do URL",
        "Médio",
        "Sessões no URL vazam por logs, Referer e links partilhados.",
        _code_steps(
            "Configurar o rastreio de sessão só por cookie (desativar URL rewriting).",
            "Redirecionar URLs com o parâmetro para a versão sem ele.",
        ),
        owner=lambda platform, group: "Equipa da aplicação",
    ),
    "TLS-HTTP-001": Playbook(
        "Redirecionar HTTP para HTTPS",
        "Baixo",
        "Os visitantes que entram por HTTP ficam sem proteção.",
        lambda platform, group: [
            f"Configurar um redirecionamento 301 de http:// para https:// em {platform.header_owner()}."
        ],
        verify=lambda domain, group: f"curl -sI http://{domain}/ | grep -iE '^(HTTP|location)'",
    ),
}


def _build(rule: str, key: str, group: dict[str, Any], platform: Platform, domain: str) -> Action:
    playbook = PLAYBOOKS.get(rule)
    bitsight = bitsight_of(rule)
    was = bitsight["assessment"] if bitsight["vector"] and "Security" in bitsight["vector"] else None
    if playbook is None:
        return Action(
            key, group["title"], group["severity"], platform.header_owner(), "Médio", group["title"],
            [group["remediation"]], f"curl -sI https://{domain}/", bitsight=was, rules=[rule],
        )  # fmt: skip
    snippet, language = ("", "text")
    if playbook.snippet:
        snippet, language = playbook.snippet(platform, group)
    elif playbook.header and playbook.value:
        snippet, language = header_snippet(platform, playbook.header, playbook.value)
    verify = (
        playbook.verify(domain, group)
        if playbook.verify
        else _curl(domain, playbook.header or ("content-security-policy" if rule.startswith("CSP") else ""))
    )
    title = playbook.title + (f" `{group['cookie']}`" if group.get("cookie") else "")
    return Action(
        key=key,
        title=title,
        severity=group["severity"],
        owner=playbook.owner(platform, group) if playbook.owner else platform.header_owner(),
        effort=playbook.effort,
        why=playbook.why,
        steps=playbook.steps(platform, group),
        verify=verify,
        snippet=snippet,
        snippet_language=language,
        bitsight=was,
        rules=[rule],
    )


def _merge(actions: dict[str, Action], action: Action, domain: str, pages: int) -> None:
    current = actions.setdefault(action.key, action)
    if domain not in current.domains:
        current.domains.append(domain)
    current.pages += pages
    if SEVERITY_ORDER.get(action.severity, 9) < SEVERITY_ORDER.get(current.severity, 9):
        current.severity = action.severity


def _is_necessary(category: str) -> bool:
    return any(hint in category.lower() for hint in NECESSARY_HINTS)


def _onetrust_actions(reports: list[tuple[str, dict[str, Any]]]) -> list[Action]:
    missing: dict[str, set[str]] = {}
    uncategorized: dict[str, set[str]] = {}
    before_consent: dict[str, set[str]] = {}
    not_configured: list[str] = []
    for domain, report in reports:
        cookies = report.get("cookies", {})
        if cookies.get("classification", {}).get("status") == "not_configured":
            not_configured.append(domain)
        for cookie in cookies.get("inventory", []):
            info = cookie.get("classification") or {}
            status = info.get("status")
            if status == "not_found":
                missing.setdefault(cookie["name"], set()).add(domain)
            elif status == "uncategorized":
                uncategorized.setdefault(cookie["name"], set()).add(domain)
            elif status == "classified" and not _is_necessary(str(info.get("category") or "")):
                before_consent.setdefault(f"{cookie['name']} ({info.get('category')})", set()).add(domain)
    owner = "OneTrust · Cookie Consent"
    actions = []
    if before_consent:
        actions.append(
            Action(
                "ONETRUST-BEFORE-CONSENT",
                "Cookies não essenciais definidos antes do consentimento",
                "High",
                f"{owner} + equipa da aplicação",
                "Médio",
                "A análise nunca aceita cookies, por isso estes Set-Cookie chegaram antes de qualquer consentimento "
                "(risco RGPD/ePrivacy).",
                [
                    "Cookies: " + ", ".join(sorted(before_consent)) + ".",
                    "Confirmar a categoria no OneTrust; se estiver correta, impedir que o servidor os defina antes "
                    "do consentimento (ou ativar o bloqueio automático do OneTrust para os scripts que os criam).",
                    "Se a categoria estiver errada, corrigi-la no OneTrust.",
                ],
                "Voltar a analisar: os cookies não devem aparecer sem consentimento.",
                domains=sorted(set().union(*before_consent.values())),
                pages=len(before_consent),
            )
        )
    if uncategorized:
        actions.append(
            Action(
                "ONETRUST-UNCATEGORIZED",
                "Categorizar cookies no OneTrust",
                "Medium",
                owner,
                "Baixo",
                "Cookies sem categoria não são controlados pelo banner de consentimento.",
                [
                    "Cookies: " + ", ".join(sorted(uncategorized)) + ".",
                    "Atribuir a categoria em Cookie Consent > Cookies (ou pela API Update Cookie, "
                    f"`{ONETRUST_UPDATE_COOKIE}`, com o ID da categoria).",
                    "Publicar o script de consentimento do domínio.",
                ],
                "Voltar a analisar com a classificação OneTrust ligada.",
                domains=sorted(set().union(*uncategorized.values())),
                pages=len(uncategorized),
            )
        )
    if missing:
        actions.append(
            Action(
                "ONETRUST-NOT-FOUND",
                "Registar no OneTrust os cookies em falta",
                "Medium",
                owner,
                "Baixo",
                "Cookies que o OneTrust não conhece ficam fora do banner e do registo de cookies.",
                [
                    "Cookies: " + ", ".join(sorted(missing)) + ".",
                    "Executar um novo scan do domínio no OneTrust ou acrescentar os cookies manualmente.",
                    "Categorizar e publicar o script de consentimento.",
                ],
                "Voltar a analisar com a classificação OneTrust ligada.",
                domains=sorted(set().union(*missing.values())),
                pages=len(missing),
            )
        )
    if not_configured:
        actions.append(
            Action(
                "ONETRUST-NOT-CONFIGURED",
                "Ligar a classificação OneTrust às análises",
                "Info",
                "Equipa de segurança",
                "Baixo",
                "Sem a OneTrust não é possível saber se os cookies estão registados e categorizados.",
                [
                    "Criar no OneTrust um cliente de API com o scope COOKIE_READ.",
                    "Definir ONETRUST_HOSTNAME, ONETRUST_CLIENT_ID e ONETRUST_CLIENT_SECRET e repetir a análise.",
                ],
                "A página Cookies do domínio mostra as categorias.",
                domains=sorted(not_configured),
            )
        )
    return actions


def _link_report_only_policy(actions: dict[str, Action]) -> None:
    """A report-only policy being tested is usually the way out of unsafe-eval/unsafe-inline: rank it with them."""
    report_only = actions.get("CSP-004")
    unsafe = [actions[key] for key in ("CSP-002", "CSP-003") if key in actions]
    if not report_only or not unsafe:
        return
    report_only.severity = "High"
    report_only.why += " Promovê-la é o caminho para resolver: " + "; ".join(a.title for a in unsafe) + "."
    for action in unsafe:
        action.steps.insert(
            0, 'Já existe uma CSP Report-Only em teste: ver a ação "Passar a CSP Report-Only a obrigatória".'
        )


def build_actions(reports: Iterable[dict[str, Any]]) -> list[Action]:
    """One action per rule (per cookie for cookie rules) across all reports, highest priority first."""
    entries = [(urllib.parse.urlsplit(r["target"]).hostname or r["target"], r) for r in reports]
    actions: dict[str, Action] = {}
    for domain, report in entries:
        platform = platform_of(report)
        for group in report["groups"]:
            rule = group["rule"]
            key = f"{rule}:{group['cookie']}" if group.get("cookie") else rule
            _merge(actions, _build(rule, key, group, platform, domain), domain, group["count"])
    _link_report_only_policy(actions)
    result = list(actions.values()) + _onetrust_actions(entries)
    result.sort(key=lambda a: (-a.score, SEVERITY_ORDER.get(a.severity, 9), a.title))
    return result


def aem_cdn_config(actions: Iterable[Action]) -> str:
    """A cdn.yaml combining every header the plan asks to set, for AEM as a Cloud Service."""
    headers: dict[str, str] = {}
    for action in actions:
        playbook = PLAYBOOKS.get(action.rules[0]) if action.rules else None
        if not (playbook and playbook.header and playbook.value) or playbook.header.endswith("Report-Only"):
            continue
        # preload is never written to a deployable file: it binds every subdomain and is hard to undo.
        headers[playbook.header] = HSTS if playbook.header == "Strict-Transport-Security" else playbook.value
    lines = [
        "# Suggested by agent-security. Review, then deploy with a Cloud Manager Config Pipeline (dev, stage, prod).",
        "# CSP changes are not included: promote or adjust the policy by hand after reviewing violation reports.",
        "# HSTS preload is left out on purpose: add '; preload' only once every subdomain serves HTTPS.",
        'kind: "CDN"',
        'version: "1"',
        "data:",
        "  responseTransformations:",
        "    rules:",
        "      - name: security-headers",
        "        when:",
        "          reqProperty: path",
        "          like: '*'",
        "        actions:",
    ]
    for header, value in sorted(headers.items()):
        lines += ["          - type: set", f"            respHeader: {header}", f"            value: {_yaml(value)}"]
    return "\n".join(lines) + "\n" if headers else ""


def action_rows(actions: Iterable[Action], state: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Flat rows for tables and CSV export."""
    return [
        {
            "Prioridade": action.priority,
            "Ação": action.title.replace("`", ""),
            "Responsável": state.get(action.key, {}).get("owner") or action.owner,
            "Esforço": action.effort,
            "Severidade": action.severity,
            "BitSight": action.bitsight or "—",
            "Domínios": ", ".join(action.domains),
            "Páginas": action.pages,
            "Estado": state.get(action.key, {}).get("status") or STATUSES[0],
            "Nota": state.get(action.key, {}).get("note") or "",
            "Chave": action.key,
        }
        for action in actions
    ]


def markdown_plan(actions: Iterable[Action], state: dict[str, dict[str, Any]], title: str) -> str:
    lines = [f"# {title}", ""]
    for action in actions:
        status = state.get(action.key, {}).get("status") or STATUSES[0]
        lines += [
            f"## [{action.priority}] {action.title}",
            "",
            f"- **Responsável:** {state.get(action.key, {}).get('owner') or action.owner}",
            f"- **Estado:** {status} · **Esforço:** {action.effort} · **Severidade:** {action.severity}",
            f"- **Domínios:** {', '.join(action.domains)} ({action.pages} páginas)",
        ]
        if action.bitsight:
            lines.append(f"- **BitSight (WAS):** {action.bitsight}")
        lines += ["", action.why, ""]
        lines += [f"{n}. {step}" for n, step in enumerate(action.steps, start=1)]
        if action.snippet:
            lines += ["", f"```{action.snippet_language}", action.snippet.rstrip(), "```"]
        lines += ["", f"**Verificação:** `{action.verify}`", ""]
    return "\n".join(lines)
