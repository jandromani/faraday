# FARADAY — Estado verificado del roadmap (32 épicas)

**Corte inicial:** 2026-10-28 · **Actualización v0.96:** nuevos controles de operación y evals en rama de release · **Fuente canónica publicada:** `master` en `79e29f2119e3720a2c0126ded6f48a8b976af4e3` (v0.95.1 Secure Pilot hardening).

> Este documento es una auditoría de estado, **no** una certificación de seguridad, una afirmación de producción ni un porcentaje de preparación para empresas. Distingue código publicado (G), pruebas locales (L) y pendientes. «Parcial» significa que hay código o evidencia que cubren solo una parte de la épica original; **no significa épica cerrada**.

## Evidencias verificadas

- **G:** GitHub master `79e29f21`, v0.95.1; CI de la rama y del PR #2 aprobadas, incluidos Node 22, Node 24 y `network-isolation` con Docker: https://github.com/jandromani/faraday/actions/runs/40785194214 . El aislamiento **solo** se demuestra para la topología Docker sintética.
- **G:** v0.95 fue fusionada por PR #1; v0.95.1 por PR #2. **116/116** tests Node locales + **100/100** evaluaciones MCP sintéticas; **40** operaciones de backend en dicho corpus. El backend ahora firma evidencias independientes del recibo del gateway y existe conciliación mediante consulta de estado, sin volver a ejecutar la operación. Documentación: `agentic/docs/V0951_EVIDENCE_RECOVERY.md`. No hay herramienta de cliente ni efectos productivos atestados.
- **G:** v0.8 lab: **1000 escenarios** deterministas, **650 checks PASS, 0 FAIL, 350 GAP**. Los GAP no son aprobados. No constituyen 1000 ataques independientes contra una infraestructura real.
- **G:** el paquete `agentic/package.json` mantiene `private: true`. No hay publicación npm pública verificada.
- **Ninguna de las 32 épicas originales está completamente cerrada** con todos los criterios empresariales contemplados. **27** tienen una implementación parcial/prototipo; **5** carecen de su capacidad central. Estas cifras son una clasificación de backlog, no una métrica de seguridad.


## Actualización v0.96 — Evidencias adicionales

- **E17:** `LocalBudget` (SQLite) se consume tras autorización criptográfica y antes del backend; sin cuota, denegar por defecto en el piloto configurado. No es distribuido.
- **E18:** aprobaciones duales firmadas Ed25519 por **operadores sintéticos**, ligadas a capacidad, recurso, argumentos y expiración. El Docker pilot exige ambas; no hay aprobación humana mediante SSO.
- **E19:** `LocalSentinel` mantiene stop persistente, cuarentena temporal y log encadenado; los eventos NO son inmutables frente a un editor privilegiado de SQLite.
- **E26:** mutación reproducible de 320 capacidades, 320 firmas y 120 argumentos, incluida la corrección de Base64URL no canónica. NO equivale a fuzzing guiado por cobertura.
- **Release gate:** `npm run test:all` y `npm run pilot:docker` deben pasar en Node 22/24/Docker para considerar integrada esta versión. No confundir 760 mutaciones con 760 ataques independientes en producción.
- **Estado empresarial:** ninguno de E17/E18/E19/E26 se ha cerrado al 100 % original; E16, E21, E31 y E32, entre otros, siguen pendientes.

## Resumen ejecutivo

| Fase | Épicas | Parciales | Capacidad central pendiente | Evidencia principal | Próximo bloqueo |
| --- | --- | ---: | ---: | --- | --- |
| F0 Foundations | E01–E04 | 4 | 0 | Docs y tests de seguridad | Especificación integral de interfaces, riesgos y privacidad |
| F1 Universal Plug & Use | E05–E08 | 3 | 1 | CLI, MCP stdio/HTTP bridge, SQLite Graph, Contracts | Adapters framework reales y conformidad externa |
| F2 Trust Boundary | E09–E14 | 6 | 0 | PoP Ed25519, policy, Docker, doble firma v0.95.1 | SPIFFE/OIDC, claves KMS y herramientas reales |
| F3 Reliable Runtime | E15–E19 | 4 | 1 | Idempotencia v0.95.1, cuotas locales, aprobación dual y Sentinel v0.96 | HA y flujo empresarial de aprobaciones/incidentes |
| F4 Agent Intelligence | E20–E22 | 2 | 1 | TrustDiff, structural impact, asesor opcional free | TimeMachine, evaluación causal y MemoryGuard |
| F5 FARADAY Lab | E23–E27 | 5 | 0 | 12 actores, 1000 escenarios, 100 evals de piloto, 760 mutaciones v0.96 | Fuzzing guiado, chaos sistemático y benchmarks externos |
| F6 Product Engineering | E28–E30 | 3 | 0 | GitHub CI, visor local, npm pack privado | Supply-chain verificable, consola enterprise, distribución |
| F7 Enterprise & Launch | E31–E32 | 0 | 2 | No existe piloto real ni acreditación | SSO/tenancy, pilotos, auditoría independiente y GTM |
| **Total** | **32** | **27** | **5** | **0 épicas cerradas al alcance original** | |

## Detalle por épica

| ID | Épica | Estado | Realizado (G=GitHub, L=solo local) | Pendiente para cerrar |
| --- | --- | --- | --- | --- |
| E01 | Product definition / Threat model | Parcial | G: `agentic/SECURITY.md`, docs v0.8/v0.9 de límites y riesgos | Threat modeling STRIDE completo, matriz amenaza-control-prueba, seguridad de producto |
| E02 | Core architecture / data model | Parcial | G: módulos Graph/Authority/Python; L: servicios de piloto MCP | Plano de control/datos formal, esquema universal versionado, unificación de stacks |
| E03 | Security by design | Parcial | G: validaciones de policy, firmas, replay, SSRF y CI Docker; L: MCP piloto | Invariantes globales, cobertura de toda entrada/salida y análisis independiente |
| E04 | Privacy / governance | Parcial | G: registros minimizados, pseudónimos, permisos SQLite, consentimiento IA | Cifrado, DLP avanzado, tenancy, retención y eliminación verificables |
| E05 | Universal installer | Parcial | G: `init`, `doctor`, `onboard`, instrumentación reversible, `dry-run` | Distribución multiplataforma probada, instalador oficial, onboarding real medido |
| E06 | MCP compatibility | Parcial | G: proxy stdio, bridge Streamable HTTP JSON/SSE sintético; L: subset protegido `/mcp` | Protocolo completo, OAuth, SSE avanzado, conformidad externa |
| E07 | Framework adapters | **Pendiente** | G: descubrimiento de archivos de configuración de clientes; no adapters SDK propios | Integraciones verificadas LangGraph, CrewAI, OpenAI Agents, n8n, HTTP directo |
| E08 | Living Agent Graph | Parcial | G: topología, SQLite, trazas mínimas, Contracts, exportación, TrustDiff | Descubrimiento universal, relaciones causales completas, histórico y blast-radius probado |
| E09 | Agent identity / delegation | Parcial | G: claves de agente Ed25519 fijadas y prueba criptográfica de posesión | SPIFFE/OIDC real, attestation, delegación interagentes, revocación dinámica |
| E10 | Authority / policy engine | Parcial | G: capacidades firmadas y políticas de ejemplo por recurso; L: validación en MCP protegido | Motor general de políticas, múltiples recursos/tenants y gestión de políticas |
| E11 | Mandatory gateway / no bypass | Parcial | G: prueba Docker de separación de redes v0.9; L: MCP protegido | Asegurar rutas directas en despliegues reales, OAuth y red/credenciales generales |
| E12 | Secrets broker | Parcial | G: credencial sintética backend solo en gateway, emisor separado | Vault/KMS, emisión efímera, rotación, revocación, broker en producción |
| E13 | FARADAY Enclave | Parcial | G: aislamiento de red Docker en un fixture; L: compose de piloto | Sandbox endurecido, límites de recursos, filesystem, tenancy, attestation |
| E14 | Verifiable receipts | Parcial **G** | G: recibo Ed25519 del gateway con attestation Ed25519 independiente del backend, ambas verificables offline | KMS, cadena auditable fuerte y prueba independiente de efectos reales |
| E15 | Idempotency / semantics | Parcial **G** | G: SQLite backend idempotente; journal y reconciliación read-only de resultados inciertos conservando historia | HA, reconciliación distribuida, transacciones sobre herramientas reales y compensación |
| E16 | High availability / recovery | **Pendiente** | L: marca `upstream-uncertain` evita reintento ciego; no HA | Arquitectura distribuida, failover, backups, RPO/RTO, resiliencia |
| E17 | Resource / cost governance | Parcial | G v0.96: cuotas persistentes por agente en el gateway MCP sintético, más guard de IA gratis | Límites distribuidos por tenant/CPU/tokens, alertas y medición real |
| E18 | Human approval / governance | Parcial | G v0.96: dos firmas offline Ed25519, quorum, roles, caducidad y vinculación exacta a capacidad y argumentos | Humanos/identidad empresarial verificados, UI, revocación, flujo de aprobación real |
| E19 | Sentinel / incident response | Parcial | G v0.96: parada de emergencia, cuarentena por denegaciones y cadena local de eventos con hash | SIEM, revocación de identidades, HA y evidencias ancladas externamente |
| E20 | Preflight / impact engine | Parcial | G: Contracts structural diff, TrustDiff y asesor IA opcional | Simulación antes de ejecutar, impacto causal y pruebas generadas por riesgo |
| E21 | TimeMachine | **Pendiente** | G: telemetría parcial; no replay de workflows | Grabación determinista, mocks, versiones y reproducción de incidentes |
| E22 | MemoryGuard / free AI | Parcial | G: asesor OpenRouter `free` opcional, metadatos reducidos | Contradicción/contaminación RAG, procedencia, expiración y evals de memoria |
| E23 | Dummy agent factory | Parcial | G: 12 actores y servidor MCP sintético, fixture local | Simulador multiagente realista con reloj/red controlados, extensiones |
| E24 | Offensive evals | Parcial | G: escenarios de seguridad deterministas con lagunas explícitas; L: 100 casos MCP criptográficos | Agentes de ataque adaptativos, corpus amplio de exploits, red team |
| E25 | Compatibility lab | Parcial | G: matriz estática y pruebas con fixtures MCP | Suites con clientes/proveedores reales, OS matrix, conformidad |
| E26 | Fuzzing / chaos | Parcial | G v0.96: 760 mutaciones adversariales deterministas de firmas, capacidades y alcance; regresión Base64URL no canónica | Coverage-guided fuzzing, mutación de políticas completa, chaos distribuido y pruebas de estrés |
| E27 | Benchmarks / scoreboard | Parcial | G: reportes de tests y 1000 escenarios; L: informe de 100 evals MCP | p95/throughput, comparación competidores, false allow, costes medidos |
| E28 | Secure supply chain | Parcial | G: GitHub Actions Node 22/24, empaquetado local, sin dependencia npm runtime | SBOM, firmas, SLSA, secret scans, branch protections, releases firmadas |
| E29 | Control Console | Parcial | G: visor local HTTP protegido por token en loopback | RBAC, políticas, operaciones, approvals, receipts y UX empresarial |
| E30 | Distribution / DX | Parcial | G: documentación, CLI, npm pack privado, demos; L: paquete v0.95 | Npm público, instaladores OS, documentación con pruebas externas, Helm |
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
