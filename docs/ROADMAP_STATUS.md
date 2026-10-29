# FARADAY — Estado verificado del roadmap (32 épicas)

## Actualización v0.99.4 — Decisiones arquitectónicas A–D (2026-10-29)

**PR #10 fusionada:** https://github.com/jandromani/faraday/pull/10. Commit de merge `310aadb3`. La release establece nuevos límites de arquitectura y gates verificables; **no** cierra nuevas épicas empresariales completas ni certifica seguridad.

- **A (E02/E07/E08/E14/E23/E29):** cuatro APIs internas y versionadas: Connect, Authority, Evidence y Lab. Son *facades* sobre `lib/*` con compatibilidad legacy, **no servicios independientes**. [ADR-001](../agentic/docs/ADR-001-FOUR-COMPONENTS.md).
- **B (E02/E10/E11/E13):** comparación formal de agentgateway vs Envoy ext_authz. Puerto opcional de decisión externa con rechazo ante errores o timeouts; **no integrado en el gateway de ejecución** para evitar una garantía de no-bypass falsa. [ADR-002](../agentic/docs/ADR-002-GATEWAY-MAKE-OR-BUY.md).
- **C (E01/E03/E04/E08/E28):** mapa OWASP ASI01–ASI10 con riesgos residuales, futura interoperabilidad OWASP ACS y proyección de spans MCP OpenTelemetry metadata-only. **No** se afirma conformidad ACS, OTLP o OWASP. [ADR-003](../agentic/docs/ADR-003-STANDARDS-TELEMETRY.md).
- **D (E03/E24/E26/E27/E28):** cuatro clases de evidencia separadas; fallo de bypass bloquea *Developer Preview* independientemente del número de unit tests; `enterprise` exige firma externa verificada con raíz de confianza. CI con pruebas Node, OAuth y Docker. [ADR-004](../agentic/docs/ADR-004-ASSURANCE-GATES.md).
- **Validación:** 228/228 tests Node y regresión total local; CI `FARADAY Architecture and Blocking Assurance` verde en la rama de PR. La CI en master se ejecuta después del merge.
- **Operación pendiente:** hacer obligatorio el nuevo job en GitHub branch protection/rulesets desde una cuenta administradora. Añadir el workflow no activa automáticamente el bloqueo en las reglas de rama.


## Actualización v0.99.3 — HTTP OAuth Resource Boundary (2026-10-29)

- **E06 — MCP Streamable HTTP (parcial)**: `server/discover` modern 2026-07-28 con resultado `supportedVersions`, `resultType`, metadatos de servidor; `tools/list`/`tools/call` modern JSON; `initialize` y llamadas 2025-11-25 **solo en subconjunto sin gestión integral de sesiones/SSE**. No conformidad universal.
- **E09/E10/E11 — Identidad/autoridad/gateway (parcial)**: módulo `PinnedOAuthResource` opt-in con JWT EdDSA/RS256, claves públicas JWKS estáticas, `iss`, `aud`, `sub`, `client_id`, `exp`, scopes read/execute, metadata RFC9728 y desafío RFC6750. La ejecución requiere **tanto JWT válido como capacidad FARADAY Ed25519**, y `sub` coincide con identidad del agente; la autorización decide el scope usando el cuerpo JSON-RPC, no cabeceras no confiables. No hay servidor OAuth ni SSO real.
- **E24/E26/E27 — Pruebas y benchmarks (parcial)**: 200 casos sintéticos de ataque a tokens firmados y tests HTTP reales de loopback, con CI multinodo/multiplataforma. No equivale a red team externo, throughput productivo ni latencia p95 de red.
- **E05 — Instalador:** Sin ampliación de su alcance original en esta release.
- **Pendiente v1.0:** OAuth login/PKCE/CIMD desde clientes, renovación JWKS y revocación, scopes jerárquicos, transporte SSE/MRTR, integración IdP y clientes externos, red no-bypass validada fuera de fixtures, auditoría independiente.
- Evidencia: `agentic/docs/V0993_HTTP_OAUTH.md`, `agentic/tests/mcp-oauth-resource.test.js`, `agentic/scripts/oauth-attack-evals.mjs`, `.github/workflows/mcp-http-oauth.yml`.


## Actualización v0.99.2 — E05/E06 comprobadas externamente (2026-10-29)

- Rama `feature/v0992-mcp-live-interop`, [GitHub Actions 40857495831](https://github.com/jandromani/faraday/actions/runs/40857495831): **4/4 jobs PASS**, además de Graph, Security y matriz previa de 15 entregables aprobadas en la rama.
- **E05:** instalación en frío desde paquete npm local, instalación offline, `init`, instrumentación, reversión y `doctor` en Linux, macOS y Windows: tiempos de fixture **1.535 / 2.349 / 5.265 s**.
- **E06:** descubrimiento y enumeración de herramientas vía stdio con servidores oficiales Filesystem 2.0.1 y Everything 2.0.1. MCP **2026-07-28** y **2025-11-25**: recuentos **14/14** y **22/16**, respectivamente. Una lectura expresamente autorizada se ejecutó correctamente.
- **Cierre limitado:** se cierran las capacidades acotadas de instalación en CI y descubrimiento stdio. **E05/E06 completas siguen parciales**: transporte HTTP y OAuth, extensiones, clientes reales y onboarding humano no validados.
- Evidencias: `agentic/docs/V0992_LIVE_MCP_INTEROP.md` y `agentic/docs/V0992_CI_EVIDENCE.json`.


## Actualización verificada v0.99.1 — 15 gates de Developer Preview (29/10/2026)

**PR #7 fusionada en master:** https://github.com/jandromani/faraday/pull/7 . Contratos de aceptación versionados en `agentic/docs/EPIC_CLOSURE_SCOPE_V1.json`; test técnico en `agentic/tests/closure-acceptance.test.js`; informe reproducible en `agentic/scripts/epic-closure-report.mjs`. CI multiplataforma **5/5 aprobada** (Ubuntu Node 22/24, macOS Node 24, Windows Node 24, regresión Linux): https://github.com/jandromani/faraday/actions/runs/40841462167 . CI Graph y Security también aprobadas sobre el commit de PR.

**15/15 comprobaciones técnicas de alcance limitado aprobadas:** E01, E05, E06, E07, E08, E10, E14, E17, E20, E21, E23, E25, E26, E27, E28. Ocho eran candidatos a cierre de componente existente y siete requerían validación adicional. **Esto no cierra al 100% las 15 épicas originales**: sigue pendiente la infraestructura empresarial, pruebas externas y certificaciones. `enterpriseClosed: 0` por diseño. El corpus sintético anterior mantiene **350 GAP** explícitos.

**Hallazgos corregidos durante CI:** mapa de pruebas que no coincidía con archivos publicados; conexiones SQLite sin cerrar antes de limpiar directorios en Windows; invocación de npm en Windows; contención de rutas en auditoría del paquete basada erróneamente en separadores POSIX. Paquete `private: true`: sin publicación a npm público. Ver [definición de cierre](../agentic/docs/EPIC_CLOSURE_V0991.md).


**Corte:** 2026-10-29 · **Actualización v0.98:** adaptadores Python LangGraph/CrewAI/OpenAI Agents con pruebas de SDK reales en CI; PR #5. Alcance: integración opt-in, no enforcement obligatorio ni certificación de producción.

> Este documento es una auditoría de estado, **no** una certificación de seguridad, una afirmación de producción ni un porcentaje de preparación para empresas. Distingue código publicado (G), pruebas locales (L) y pendientes. «Parcial» significa que hay código o evidencia que cubren solo una parte de la épica original; **no significa épica cerrada**.

## Evidencias verificadas

- **G:** GitHub master `79e29f21`, v0.95.1; CI de la rama y del PR #2 aprobadas, incluidos Node 22, Node 24 y `network-isolation` con Docker: https://github.com/jandromani/faraday/actions/runs/40785194214 . El aislamiento **solo** se demuestra para la topología Docker sintética.
- **G:** v0.95 fue fusionada por PR #1; v0.95.1 por PR #2. **116/116** tests Node locales + **100/100** evaluaciones MCP sintéticas; **40** operaciones de backend en dicho corpus. El backend ahora firma evidencias independientes del recibo del gateway y existe conciliación mediante consulta de estado, sin volver a ejecutar la operación. Documentación: `agentic/docs/V0951_EVIDENCE_RECOVERY.md`. No hay herramienta de cliente ni efectos productivos atestados.
- **G:** v0.8 lab: **1000 escenarios** deterministas, **650 checks PASS, 0 FAIL, 350 GAP**. Los GAP no son aprobados. No constituyen 1000 ataques independientes contra una infraestructura real.
- **G:** el paquete `agentic/package.json` mantiene `private: true`. No hay publicación npm pública verificada.
- **Ninguna de las 32 épicas originales está completamente cerrada** con todos los criterios empresariales contemplados. **30** tienen una implementación parcial/prototipo; **2** carecen de su capacidad central. Estas cifras son una clasificación de backlog, no una métrica de seguridad.


## Actualización v0.96 — Evidencias adicionales

- **E17:** `LocalBudget` (SQLite) se consume tras autorización criptográfica y antes del backend; sin cuota, denegar por defecto en el piloto configurado. No es distribuido.
- **E18:** aprobaciones duales firmadas Ed25519 por **operadores sintéticos**, ligadas a capacidad, recurso, argumentos y expiración. El Docker pilot exige ambas; no hay aprobación humana mediante SSO.
- **E19:** `LocalSentinel` mantiene stop persistente, cuarentena temporal y log encadenado; los eventos NO son inmutables frente a un editor privilegiado de SQLite.
- **E26:** mutación reproducible de 320 capacidades, 320 firmas y 120 argumentos, incluida la corrección de Base64URL no canónica. NO equivale a fuzzing guiado por cobertura.
- **Release gate:** `npm run test:all` y `npm run pilot:docker` deben pasar en Node 22/24/Docker para considerar integrada esta versión. No confundir 760 mutaciones con 760 ataques independientes en producción.
- **Estado empresarial:** ninguno de E17/E18/E19/E26 se ha cerrado al 100 % original; E16 y E21 tienen nuevas implementaciones parciales; E31 y E32 permanecen pendientes.

## Actualización v0.97 — Evidencia y límites

- **PR #4 fusionada:** `https://github.com/jandromani/faraday/pull/4` (squash `1588447c`); CI Graph Node 22 y 24 y job Docker `network-isolation` aprobaron en `https://github.com/jandromani/faraday/actions/runs/40788817314`. El aislamiento continúa limitado a la topología sintética.
- **E21:** `agentic/lib/timemachine.js` ofrece replay exclusivamente offline de intenciones sintéticas, hash chain y metadatos protegidos frente a alteración casual. **No hay firma de procedencia, no hay captura real de workflows ni llamada externa.**
- **E16:** `agentic/lib/recovery-inspector.js` consulta en modo solo lectura estados SQLite y señala reservas huérfanas e incertidumbre. **Nunca reintenta ni resuelve automáticamente; no es alta disponibilidad.**
- **E27:** `agentic/lib/benchmarks.js` mide operaciones locales y presenta mediana/p95. **No** mide latencia de un gateway MCP real ni constituye SLA.
- **E28:** `agentic/scripts/release-audit.mjs` genera SBOM inventario SPDX 2.3 con SHA-256 y rechazo de secretos/paquetes accidentalmente públicos. **No es SBOM firmado, no es attestación SLSA ni auditoría independiente.**
- **Tests:** suite local ampliada v0.97 157/157; tests efectivamente ejecutados en la CI Node 22 de PR #4: 143/143. Diferencia por pruebas locales adicionales no publicadas, no deben confundirse. Las 350 lagunas del laboratorio v0.8 siguen siendo lagunas.

## Actualización v0.98 — E07 y E25 (frameworks)

- **E07:** `agentic/python/faraday_adapters` incorpora adaptadores **opt-in** sobre APIs públicas, sin monkey patch, para LangGraph `StateGraph` (nodos/tools), CrewAI hooks de herramienta y OpenAI Agents SDK `FunctionTool`/`RunHooks`. No interceptan llamadas directas no instrumentadas.
- **E08:** `faraday adapters ingest` valida esquema de metadatos pseudonimizados y lo integra en SQLite Graph (límites de tamaño, symlinks rechazados, importación transaccional, deduplicación por hash de archivo).
- **E25:** CI [real-SDK adapter compatibility](https://github.com/jandromani/faraday/actions/runs/40836798238) con **3/3 jobs** correctos; se instalan librerías reales pero no se realiza un workflow multiagente con proveedor LLM ni se prueba compatibilidad completa.
- **Calidad:** 160/160 pruebas Node, 8/8 Python locales, CI Node 22/24 y Docker aprobadas en [Graph CI](https://github.com/jandromani/faraday/actions/runs/40836798328). **Ninguna de las 32 épicas está completamente cerrada en su alcance original.**

## Resumen ejecutivo

| Fase | Épicas | Parciales | Capacidad central pendiente | Evidencia principal | Próximo bloqueo |
| --- | --- | ---: | ---: | --- | --- |
| F0 Foundations | E01–E04 | 4 | 0 | Docs y tests de seguridad | Especificación integral de interfaces, riesgos y privacidad |
| F1 Universal Plug & Use | E05–E08 | 4 | 0 | CLI, MCP stdio/HTTP bridge, SQLite Graph, Contracts y adapters Python opt-in v0.98 | Validación end-to-end con workflows reales y conformidad externa |
| F2 Trust Boundary | E09–E14 | 6 | 0 | PoP Ed25519, policy, Docker, doble firma v0.95.1 | SPIFFE/OIDC, claves KMS y herramientas reales |
| F3 Reliable Runtime | E15–E19 | 5 | 0 | Idempotencia v0.95.1, cuotas locales, aprobación dual y Sentinel v0.96 | HA y flujo empresarial de aprobaciones/incidentes |
| F4 Agent Intelligence | E20–E22 | 3 | 0 | TrustDiff, structural impact, asesor opcional free | TimeMachine, evaluación causal y MemoryGuard |
| F5 FARADAY Lab | E23–E27 | 5 | 0 | 12 actores, 1000 escenarios, 100 evals de piloto, 760 mutaciones v0.96 | Fuzzing guiado, chaos sistemático y benchmarks externos |
| F6 Product Engineering | E28–E30 | 3 | 0 | GitHub CI, visor local, npm pack privado | Supply-chain verificable, consola enterprise, distribución |
| F7 Enterprise & Launch | E31–E32 | 0 | 2 | No existe piloto real ni acreditación | SSO/tenancy, pilotos, auditoría independiente y GTM |
| **Total** | **32** | **30** | **2** | **0 épicas cerradas al alcance original** | |

## Detalle por épica

| ID | Épica | Estado | Realizado (G=GitHub, L=solo local) | Pendiente para cerrar |
| --- | --- | --- | --- | --- |
| E01 | Product definition / Threat model | Parcial | G: `agentic/SECURITY.md`, docs v0.8/v0.9 de límites y riesgos | Threat modeling STRIDE completo, matriz amenaza-control-prueba, seguridad de producto |
| E02 | Core architecture / data model | Parcial | G: módulos Graph/Authority/Python; L: servicios de piloto MCP | Plano de control/datos formal, esquema universal versionado, unificación de stacks |
| E03 | Security by design | Parcial | G: validaciones de policy, firmas, replay, SSRF y CI Docker; L: MCP piloto | Invariantes globales, cobertura de toda entrada/salida y análisis independiente |
| E04 | Privacy / governance | Parcial | G: registros minimizados, pseudónimos, permisos SQLite, consentimiento IA | Cifrado, DLP avanzado, tenancy, retención y eliminación verificables |
| E05 | Universal installer | Parcial | G: `init`, `doctor`, `onboard`, instrumentación reversible, `dry-run` | Distribución multiplataforma probada, instalador oficial, onboarding real medido |
| E06 | MCP compatibility | Parcial | G: proxy stdio, bridge Streamable HTTP JSON/SSE sintético; L: subset protegido `/mcp` | Protocolo completo, OAuth, SSE avanzado, conformidad externa |
| E07 | Framework adapters | Parcial **G v0.98** | G: wrappers explícitos LangGraph StateGraph; hooks oficiales CrewAI; FunctionTool/RunHooks OpenAI Agents SDK; trazas JSONL pseudonimizadas ingeridas por Graph; smoke SDK real 3/3 en CI | Workflows completos con LLM/servidores externos, varias versiones, LangChain create_agent, n8n y bypass tests en entornos reales |
| E08 | Living Agent Graph | Parcial | G: topología, SQLite, trazas mínimas, Contracts, exportación, TrustDiff | Descubrimiento universal, relaciones causales completas, histórico y blast-radius probado |
| E09 | Agent identity / delegation | Parcial | G: claves de agente Ed25519 fijadas y prueba criptográfica de posesión | SPIFFE/OIDC real, attestation, delegación interagentes, revocación dinámica |
| E10 | Authority / policy engine | Parcial | G: capacidades firmadas y políticas de ejemplo por recurso; L: validación en MCP protegido | Motor general de políticas, múltiples recursos/tenants y gestión de políticas |
| E11 | Mandatory gateway / no bypass | Parcial | G: prueba Docker de separación de redes v0.9; L: MCP protegido | Asegurar rutas directas en despliegues reales, OAuth y red/credenciales generales |
| E12 | Secrets broker | Parcial | G: credencial sintética backend solo en gateway, emisor separado | Vault/KMS, emisión efímera, rotación, revocación, broker en producción |
| E13 | FARADAY Enclave | Parcial | G: aislamiento de red Docker en un fixture; L: compose de piloto | Sandbox endurecido, límites de recursos, filesystem, tenancy, attestation |
| E14 | Verifiable receipts | Parcial **G** | G: recibo Ed25519 del gateway con attestation Ed25519 independiente del backend, ambas verificables offline | KMS, cadena auditable fuerte y prueba independiente de efectos reales |
| E15 | Idempotency / semantics | Parcial **G** | G: SQLite backend idempotente; journal y reconciliación read-only de resultados inciertos conservando historia | HA, reconciliación distribuida, transacciones sobre herramientas reales y compensación |
| E16 | High availability / recovery | Parcial **G** | G v0.97: inspector SQLite read-only que identifica reservas pendientes y resultados inciertos sin reejecución; no HA | Failover, backups, recuperación distribuida, RPO/RTO y caos de producción |
| E17 | Resource / cost governance | Parcial | G v0.96: cuotas persistentes por agente en el gateway MCP sintético, más guard de IA gratis | Límites distribuidos por tenant/CPU/tokens, alertas y medición real |
| E18 | Human approval / governance | Parcial | G v0.96: dos firmas offline Ed25519, quorum, roles, caducidad y vinculación exacta a capacidad y argumentos | Humanos/identidad empresarial verificados, UI, revocación, flujo de aprobación real |
| E19 | Sentinel / incident response | Parcial | G v0.96: parada de emergencia, cuarentena por denegaciones y cadena local de eventos con hash | SIEM, revocación de identidades, HA y evidencias ancladas externamente |
| E20 | Preflight / impact engine | Parcial | G: Contracts structural diff, TrustDiff y asesor IA opcional | Simulación antes de ejecutar, impacto causal y pruebas generadas por riesgo |
| E21 | TimeMachine | Parcial **G** | G v0.97: traza sintética encadenada, integridad de política/metadatos, replay offline bajo otra política, diff y regresiones | Captura de workloads reales, encriptación, firmas de procedencia, causalidad y replay de workflows |
| E22 | MemoryGuard / free AI | Parcial | G: asesor OpenRouter `free` opcional, metadatos reducidos | Contradicción/contaminación RAG, procedencia, expiración y evals de memoria |
| E23 | Dummy agent factory | Parcial | G: 12 actores y servidor MCP sintético, fixture local | Simulador multiagente realista con reloj/red controlados, extensiones |
| E24 | Offensive evals | Parcial | G: escenarios de seguridad deterministas con lagunas explícitas; L: 100 casos MCP criptográficos | Agentes de ataque adaptativos, corpus amplio de exploits, red team |
| E25 | Compatibility lab | Parcial **G v0.98** | G: matriz estática, fixtures MCP y tres smokes contra SDK reales (LangGraph/CrewAI/OpenAI Agents) sin LLM ni herramientas externas | Conformidad MCP y workflows completos, matriz versiones/OS, clientes/proveedores reales |
| E26 | Fuzzing / chaos | Parcial | G v0.96: 760 mutaciones adversariales deterministas de firmas, capacidades y alcance; regresión Base64URL no canónica | Coverage-guided fuzzing, mutación de políticas completa, chaos distribuido y pruebas de estrés |
| E27 | Benchmarks / scoreboard | Parcial **G** | G v0.97: microbenchmarks offline con mediana y p95 de políticas/replay; informes de 1000 escenarios | End-to-end gateway p95/throughput, hardware controlado, falsos permisos y competidores |
| E28 | Secure supply chain | Parcial **G** | G v0.97: informe SPDX 2.3 por fichero, SHA-256, gate contra secretos, distribución privada y CI Node 22/24 | Firmas, SLSA, SCA, escáner de secretos de repositorio, branch protection y releases reproducibles |
| E29 | Control Console | Parcial | G: visor local HTTP protegido por token en loopback | RBAC, políticas, operaciones, approvals, receipts y UX empresarial |
| E30 | Distribution / DX | Parcial | G: documentación, CLI, npm pack privado, demos; paquete local v0.97 | Npm público, instaladores OS, documentación con pruebas externas, Helm |
| E31 | Enterprise readiness | **Pendiente** | No hay SSO, despliegue con tenancy, SLA, auditoría externa ni certificaciones | RBAC/SSO, entornos reales, cumplimiento, seguridad independiente |
| E32 | Commercial validation / launch | **Pendiente** | No hay pilotos de cliente confirmados ni ingresos atribuibles | 3 pilotos, benchmarks competitivos, aceptación, pricing y distribución |

## Bloqueantes y secuencia de trabajo

**P0 — Integridad del repositorio (CERRADA para el piloto):** v0.95 y v0.95.1 se fusionaron mediante PR #1 y PR #2 con suites Node, evaluaciones MCP y Docker aprobadas. No supone cierre empresarial de las épicas.

**P0 — Seguridad auténtica (ABIERTA):** extender E09–E13 a identidad atestada y recursos reales de bajo riesgo bajo `default deny`, y demostrar no-bypass en cada entorno. E14–E15 ya incluyen evidencias sintéticas respaldadas por dos firmantes y conciliación sin replay; faltan KMS, HA, auditoría y semántica empresarial.

**P0 — Quality gate:** convertir 350 `GAP` en tests genuinos cuando existan los controles correspondientes; crear E26 con fuzzing/chaos y E27 con medidas reproducibles.

**P1 — Plug and use verificable:** cerrar E06–E07 con 3 runtimes reales y matrices de configuración, errores, rollback y performance. Los hallazgos de compatibilidad deben distinguirse de una prueba de conformidad.

**P1 — Operación empresarial:** E16–E19, E28–E31, seguidas de E32 con pilotos externos. Preflight/TimeMachine/MemoryGuard (E20–E22) son extensiones, **no prerrequisitos** para demostrar una frontera mínima segura.

## Criterios para una v1.0 creíble

- Ningún bypass observado en un corpus público de pruebas asociado a **una topología definida**, sin proclamar seguridad absoluta.
- Identidad/workload y credenciales separadas de la memoria del agente; políticas por acción/recurso probadas.
- Idempotencia y recovery seguros ante resultados inciertos, recibos verificables con distinción entre autorización y efecto.
- MCP/OS/frameworks soportados explícitamente con conformidad y rollback medidos.
- Red team independiente, auditoría, documentación de límites, CI/release reproducible, SBOM.
- Pilotos y métricas de valor reales. Hasta entonces **Developer Preview / Secure Pilot sintético**, no producción certificada.
