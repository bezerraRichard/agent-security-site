# agent-security

Crawler passivo de segurança HTTP. Percorre um ou mais sites **autorizados**, avalia cabeçalhos de segurança, Content-Security-Policy, cookies e conteúdo de cada página (conteúdo misto, Subresource Integrity, tokens de sessão no URL), e gera por domínio um relatório HTML e um JSON. As regras estão alinhadas com o vetor *Web Application Security* da BitSight, os cookies podem ser classificados com a API de Cookie Consent da OneTrust, e há uma consola web em Streamlit.

Funciona com ou sem proxy: tenta primeiro o proxy do sistema e, se falhar, liga-se diretamente.

## Uso autorizado

Use esta ferramenta **apenas em sites que lhe pertencem ou que tem autorização escrita para avaliar**. Mesmo sendo passiva, gera tráfego contra o alvo.

O que a ferramenta garante por desenho:

- Envia só pedidos `GET`, um de cada vez, com pausa entre pedidos (mínimo 0,2 s).
- Fica nos hostnames autorizados. Hosts adicionais só entram com `--allow-host`, e redirecionamentos para outros hosts não são seguidos.
- Respeita o `robots.txt` (incluindo `Crawl-delay`), salvo `--ignore-robots`.
- Ignora ficheiros binários e caminhos que parecem ações com efeitos (`logout`, `delete`, `unsubscribe`, ...).
- Limita as variantes de query-string por caminho e o número total de páginas.
- Não faz autenticação, não preenche formulários e não envia payloads de ataque.
- Não guarda valores de cookies: nos relatórios aparecem como `<redacted>`.

## Instalação

Requer Python 3.10 ou superior.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Para a consola, use `pip install -e ".[console]"`. Para desenvolvimento (testes, lint e tipos), use `pip install -e ".[dev]"`.

## Utilização

```powershell
# Varredura com os limites por omissão (500 páginas, profundidade 10)
agent-security https://www.example.com/

# Mais páginas, usando também o sitemap
agent-security https://www.example.com/ --max-pages 2000 --sitemap

# Incluir um subdomínio explicitamente autorizado
agent-security https://www.example.com/ --allow-host shop.example.com

# Só as páginas de uma lista aprovada, sem seguir links
agent-security https://www.example.com/ --urls-file urls.txt --max-depth 0

# Vários domínios, um a seguir ao outro, cada um com o seu relatório
agent-security www.example.com www.example.org --allow-host shop.example.org
```

Com vários domínios, cada `--allow-host` junta-se ao domínio do qual é subdomínio (`shop.example.org` → `www.example.org`), cada URL de `--urls-file` vai para o domínio que autoriza o seu host, e o resumo final lista todos os domínios. Os relatórios do mesmo lote partilham um identificador (`batch.id` no JSON).

`python -m agent_security` é equivalente ao comando `agent-security`.

O ficheiro de `--urls-file` tem um URL HTTPS por linha. Linhas vazias e comentários iniciados por `#` são ignorados, e URLs de hosts não autorizados são rejeitados.

### Opções

| Opção | Por omissão | Descrição |
|---|---|---|
| `target` | — | Um ou mais URLs ou hostnames de partida (apenas HTTPS, porta 443) |
| `--allow-host` | — | Hostname autorizado adicional (repetível) |
| `--urls-file` | — | URLs aprovados adicionais, um por linha |
| `--sitemap` | desligado | Usa também o `sitemap.xml` como ponto de partida |
| `--ignore-robots` | desligado | Não respeita o `robots.txt` |
| `--max-pages` | 500 | Máximo de páginas (1 a 5000) |
| `--max-depth` | 10 | Profundidade máxima de links (0 a 50) |
| `--delay-seconds` | 0.5 | Pausa entre pedidos (mínimo 0.2) |
| `--timeout` | 15 | Timeout de cada pedido, em segundos |
| `--retries` | 2 | Novas tentativas em falhas transitórias (0 a 5) |
| `--time-limit-minutes` | 120 | Duração máxima da varredura |
| `--proxy` / `--no-proxy` | automático | Proxy explícito ou ligação direta |
| `--fallback-direct` | desligado | Com `--proxy`, tenta ligação direta se o proxy falhar |
| `--ca-bundle` | — | Ficheiro PEM com CAs adicionais (ex.: inspeção TLS corporativa) |
| `--output-dir` | `reports` | Pasta dos relatórios |
| `--quiet` | desligado | Não escreve progresso no stderr |

### Proxy

Por omissão, a ferramenta tenta o proxy do sistema ou do ambiente (`HTTPS_PROXY`, definições do Windows) e depois a ligação direta; o relatório indica a rota usada e as tentativas falhadas. Um proxy que responda `407` conta como falha.

Use `--proxy http://proxy.example:8080` para forçar um proxy, `--no-proxy` para ligar diretamente, e `--ca-bundle` se o proxy fizer inspeção TLS.

## Consola (Streamlit)

```powershell
pip install -e ".[console]"
agent-security-console                 # abre http://localhost:8501
agent-security-console --output-dir reports --port 8502
```

A consola só escuta em `localhost` e não envia estatísticas de utilização. Usa a identidade visual do novobanco (paleta de www.novobanco.pt e o logótipo oficial, em `src/agent_security/console/novobanco.svg`); a fonte proprietária NovobancoText não é incluída. O relatório HTML usa a mesma identidade, com o logótipo embutido no próprio ficheiro (não carrega recursos externos). Tem cinco páginas:

- **Nova análise**: domínios (um por linha, com hosts adicionais opcionais na mesma linha), perfil de varredura (Rápido, Conservador, Padrão ou Personalizado), rede, OneTrust e confirmação obrigatória de autorização. A análise corre em segundo plano, com progresso por domínio e botão para cancelar.
- **Painel**: comparação dos domínios de um lote, com indicadores, severidades, avaliações BitSight e matriz de controlos.
- **Domínio**: problemas filtráveis com evidência e remediação, alinhamento BitSight, inventário de cookies, cobertura e download do HTML/JSON.
- **Histórico**: todos os relatórios da pasta, incluindo os anteriores à consola.
- **Regras e BitSight**: o catálogo de regras e o mapeamento para a BitSight.

As credenciais da OneTrust continuam a vir só do ambiente: defina as variáveis antes de abrir a consola.

## Classificação de cookies (OneTrust)

Se as variáveis abaixo estiverem definidas, cada cookie observado é consultado na API [Get List of Cookies by Criteria](https://developer.onetrust.com/onetrust/reference/getcookiesbyfilter) (apenas leitura, escopo `COOKIE_READ`), e o relatório mostra categoria, party (própria ou de terceiros), duração e descrição.

```powershell
$env:ONETRUST_HOSTNAME = "app-eu.onetrust.com"   # tem de ser *.onetrust.com
$env:ONETRUST_CLIENT_ID = "..."
$env:ONETRUST_CLIENT_SECRET = "..."
$env:ONETRUST_LANGUAGE = "pt"                    # opcional (por omissão, en)
```

As credenciais vêm **só do ambiente**: nunca as passe por argumentos nem as escreva em ficheiros. Opções: `--onetrust-language`, `--onetrust-domain-id <uuid>` (repetível, restringe a consulta a domínios do tenant) e `--no-cookie-classification`.

Só os nomes dos cookies, nunca os valores, são enviados ao seu tenant. Um cookie ausente do catálogo aparece como "Not found in OneTrust" e não é considerado uma falha de segurança. Cada execução consulta no máximo 300 nomes.

## O que é verificado

| Regra | Severidade | Verificação |
|---|---|---|
| `HDR-HSTS-001` | High | `Strict-Transport-Security` em falta |
| `HDR-HSTS-002` | Medium | HSTS com `max-age` inferior a um ano ou inválido |
| `CSP-000` | High | `Content-Security-Policy` em falta |
| `CSP-001` | Medium | CSP sem `default-src` |
| `CSP-002` | Critical | CSP permite `'unsafe-eval'` em scripts |
| `CSP-003` | High | CSP permite `'unsafe-inline'` em scripts (sem nonce, hash nem `'strict-dynamic'`, que o anulam) |
| `HDR-XCTO-001` | Medium | `X-Content-Type-Options` em falta |
| `HDR-XFO-001` | Medium | Sem `X-Frame-Options` nem `frame-ancestors` |
| `HDR-REF-001` | Low | `Referrer-Policy` em falta |
| `HDR-PP-001` | Low | `Permissions-Policy` em falta |
| `COOKIE-SECURE` | High | Cookie sem `Secure` |
| `COOKIE-HTTPONLY` | Medium | Cookie sem `HttpOnly` |
| `COOKIE-SAMESITE` | Medium | Cookie sem `SameSite` |
| `COOKIE-SAMESITE-NONE` | High | `SameSite=None` sem `Secure` (bloqueado pelos browsers) |
| `HDR-HSTS-003` | Info | HSTS sem `preload` |
| `HDR-REF-002` | Medium | `Referrer-Policy` insegura (`unsafe-url`, `no-referrer-when-downgrade`) |
| `MIXED-001` | High | Scripts, estilos ou frames carregados por HTTP numa página HTTPS |
| `MIXED-002` | Medium | Imagens ou media carregados por HTTP numa página HTTPS |
| `SRI-001` | Low | Scripts ou estilos de outros domínios sem `integrity` |
| `URL-SESSION-001` | High | Identificador de sessão no URL (o valor não é registado) |
| `TLS-HTTP-001` | High | HTTP não redireciona para HTTPS |

A CSP definida em `<meta http-equiv>` também é avaliada quando não há cabeçalho (o `frame-ancestors` de uma meta tag é ignorado, como nos browsers).

### Alinhamento BitSight

Desde 10/07/2025, o rating da BitSight usa o vetor *Web Application Security* (WAS), que substituiu o *Web Application Headers* (WAH), agora sem nota. Cada achado indica a avaliação WAS a que corresponde (por exemplo `Content Security Policy Configurations`, `Mixed Content`, `Cookie SameSite Attribute`), ou se é só do WAH legado ou não é avaliado pela BitSight. O mapeamento é aproximado e baseado na documentação pública da BitSight. A BitSight carrega apenas a página inicial de cada domínio num browser, enquanto esta ferramenta percorre o site. Não são cobertas as avaliações WAS que precisam de um browser ou de uma base de vulnerabilidades, como bibliotecas JavaScript vulneráveis.

Os problemas iguais em várias páginas são agrupados num só item, com a lista de URLs afetados.

## Relatórios

Cada execução escreve, em `--output-dir`, `site-security-report-<data UTC>.html` e `.json`; nunca sobrescreve relatórios existentes. O HTML tem resumo por severidade e por secção, inventário e classificação de cookies, detalhe de cada achado (valor atual, esperado, remediação e referências), cobertura da varredura e tabela de páginas.

O comando imprime um resumo em JSON e termina com:

| Código | Significado |
|---|---|
| `0` | Varredura completa dentro do âmbito |
| `2` | Parcial ou incompleta (limite atingido, falhas, alvo inacessível) ou argumentos inválidos |

Um estado `partial` ou `incomplete` nunca deve ser tratado como cobertura total do site.

## Limitações

- Descobre páginas apenas por links no HTML estático. Páginas geradas por JavaScript, formulários e áreas autenticadas não são cobertas.
- Não avalia protocolos nem cifras TLS (vetores BitSight de SSL/TLS); só verifica o redirecionamento de HTTP para HTTPS.
- Só aceita HTTPS na porta 443 e hostnames (não IPs).

## Desenvolvimento

```powershell
python -m unittest discover -s tests -t .
ruff check .
ruff format --check .
mypy
```

```
src/agent_security/
  cli.py        argumentos e saída        config.py     ScanConfig validada
  scan.py       orquestração da varredura network.py    rotas, retries, escopo
  crawler.py    percurso de páginas       discovery.py  robots.txt e sitemaps
  urls.py       validação de URLs         analysis.py   regras de segurança
  findings.py   agrupamento e resumos     cookies.py    inventário de cookies
  onetrust.py   classificação OneTrust    report.py     relatórios HTML/JSON
  taxonomy.py   severidades, secções e BitSight
  htmlfacts.py  CSP meta, conteúdo misto, SRI
  batch.py      vários domínios por lote
  console/      consola Streamlit (app, páginas, dados, análises em segundo plano)
tests/          um ficheiro de testes por módulo
```

O agente `HTTP Security Report` para o VS Code está em `.github/agents/` e usa este comando.
