# FARADAY — Estado verificado del roadmap (32 épicas)

**Corte:** 2026-10-28 · **Fuente canónica publicada:** `master` en `dc31333dadff4a5e938024a10c2744fe0724cf8a` (v0.9 Authority Preview) · **Candidato local:** v0.95 Secure Pilot.

> Este documento es una auditoría de estado, **no** una certificación de seguridad, una afirmación de producción ni un porcentaje de preparación para empresas. Distingue código publicado (G), artefacto local no publicado (L) y pendientes. «Parcial» significa que hay código o evidencia que cubren solo una parte de la épica original; **no significa épica cerrada**.

## Evidencias verificadas

- **G:** GitHub master `dc31333d`, v0.9. Última CI Graph aprobada: https://github.com/jandromani/faraday/actions/runs/40781540267 ; tres jobs exitosos: Node 22, Node 24 y prueba Docker `network-isolation`. El test Docker es válido **solo para la topología sintética de referencia**.
- **L:** v0.95 en artefactos locales de esta conversación, no fusionada en GitHub. `npm test` reejecutado el 28-10-2026 sobre el árbol local: **112/112 PASS**. Informe de evaluaciones: **100/100** casos sintéticos, **40** operaciones del backend de prueba. Prueba Docker v0.95 **no ejecutada** en ese entorno; topología inspeccionada estáticamente. Código local `agentic/docs/V095_SECURE_PILOT.md`.
- **G:** v0.8 lab: **1000 escenarios** deterministas, **650 checks PASS, 0 FAIL, 350 GAP**. Los GAP no son aprobados. No constituyen 1000 ataques independientes contra una infraestructura real.
- **G:** el paquete `agentic/package.json` mantiene `private: true`. No hay publicación npm pública verificada.
- **Ninguna de las 32 épicas originales está completamente cerrada** con todos los criterios empresariales contemplados. **24** tienen una implementación parcial/prototipo; **8** carecen de su capacidad central. Estas cifras son una clasificación de backlog, no una métrica de seguridad.

## Resumen ejecutivo

| Fase | Épicas | Parciales | Capacidad central pendiente | Evidencia principal | Próximo bloqueo |
| --- | --- | ---: | ---: | --- | --- |
| F0 Foundations | E01–E04 | 4 | 0 | Docs y tests de seguridad | Especificación integral de interfaces, riesgos y privacidad |
| F1 Universal Plug & Use | E05–E08 | 3 | 1 | CLI, MCP stdio/HTTP bridge, SQLite Graph, Contracts | Adapters framework reales y conformidad externa |
| F2 Trust Boundary | E09–E14 | 6 | 0 | PoP Ed25519, policy, Docker v0.9; receipts locales v0.95 | Identidad atestada, ejecución general y evidencias independientes |
| F3 Reliable Runtime | E15–E19 | 2 | 3 | Idempotencia/journal local v0.95, free-model guard | HA, human approval, Sentinel |
| F4 Agent Intelligence | E20–E22 | 2 | 1 | TrustDiff, structural impact, asesor opcional free | TimeMachine, evaluación causal y MemoryGuard |
| F5 FARADAY Lab | E23–E27 | 4 | 1 | 12 actores sintéticos, 1000 escenarios, 100 evals de piloto | Fuzzing, chaos sistemático, benchmarks externos |
| F6 Product Engineering | E28–E30 | 3 | 0 | GitHub CI, visor local, npm pack privado | Supply-chain verificable, consola enterprise, distribución |
| F7 Enterprise & Launch | E31–E32 | 0 | 2 | No existe piloto real ni acreditación | SSO/tenancy, pilotos, auditoría independiente y GTM |
| **Total** | **32** | **24** | **8** | **0 épicas cerradas al alcance original** | |

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
| E14 | Verifiable receipts | Parcial **L** | L: recibos firmados Ed25519 y verificador offline del gateway | Integrarlo/publicarlo en GitHub, firmas/ack del backend, custodia KMS, evidencia inmutable |
| E15 | Idempotency / semantics | Parcial **L** | L: SQLite backend idempotente y journal de incertidumbre de gateway | Publicación GitHub, reconciliación distribuida, efectos de herramientas reales, compensación |
| E16 | High availability / recovery | **Pendiente** | L: marca `upstream-uncertain` evita reintento ciego; no HA | Arquitectura distribuida, failover, backups, RPO/RTO, resiliencia |
| E17 | Resource / cost governance | Parcial | G: AI free-first con verificación de catálogo y bloqueo de fallback pagado | Cuotas por tenant/agente, bucles, CPU/memoria, presupuestos y alertas |
| E18 | Human approval / governance | **Pendiente** | No hay workflow de aprobación humana de acciones protegidas | Dual control, expiración, vinculación de argumentos, auditoría |
| E19 | Sentinel / incident response | **Pendiente** | G: diagnóstico local de seguridad, no detección/respuesta operativa | Detección anomalías, kill switch, cuarentena, revocación, SIEM |
| E20 | Preflight / impact engine | Parcial | G: Contracts structural diff, TrustDiff y asesor IA opcional | Simulación antes de ejecutar, impacto causal y pruebas generadas por riesgo |
| E21 | TimeMachine | **Pendiente** | G: telemetría parcial; no replay de workflows | Grabación determinista, mocks, versiones y reproducción de incidentes |
| E22 | MemoryGuard / free AI | Parcial | G: asesor OpenRouter `free` opcional, metadatos reducidos | Contradicción/contaminación RAG, procedencia, expiración y evals de memoria |
| E23 | Dummy agent factory | Parcial | G: 12 actores y servidor MCP sintético, fixture local | Simulador multiagente realista con reloj/red controlados, extensiones |
| E24 | Offensive evals | Parcial | G: escenarios de seguridad deterministas con lagunas explícitas; L: 100 casos MCP criptográficos | Agentes de ataque adaptativos, corpus amplio de exploits, red team |
| E25 | Compatibility lab | Parcial | G: matriz estática y pruebas con fixtures MCP | Suites con clientes/proveedores reales, OS matrix, conformidad |
| E26 | Fuzzing / chaos | **Pendiente** | G/L: tests de algunos fallos y replay, pero sin fuzzing ni chaos continuo | Property based, mutaciones, fallos de proceso/disco/red e invariantes |
| E27 | Benchmarks / scoreboard | Parcial | G: reportes de tests y 1000 escenarios; L: informe de 100 evals MCP | p95/throughput, comparación competidores, false allow, costes medidos |
| E28 | Secure supply chain | Parcial | G: GitHub Actions Node 22/24, empaquetado local, sin dependencia npm runtime | SBOM, firmas, SLSA, secret scans, branch protections, releases firmadas |
| E29 | Control Console | Parcial | G: visor local HTTP protegido por token en loopback | RBAC, políticas, operaciones, approvals, receipts y UX empresarial |
| E30 | Distribution / DX | Parcial | G: documentación, CLI, npm pack privado, demos; L: paquete v0.95 | Npm público, instaladores OS, documentación con pruebas externas, Helm |
| E31 | Enterprise readiness | **Pendiente** | No hay SSO, despliegue con tenancy, SLA, auditoría externa ni certificaciones | RBAC/SSO, entornos reales, cumplimiento, seguridad independiente |
| E32 | Commercial validation / launch | **Pendiente** | No hay pilotos de cliente confirmados ni ingresos atribuibles | 3 pilotos, benchmarks competitivos, aceptación, pricing y distribución |

## Bloqueantes y secuencia de trabajo

**P0 — Integridad del repositorio:** subir v0.95 de forma trazable en una rama/PR, revisar la diff con master, ejecutar su suite y **su Docker CI real**; no declarar v0.95 publicada hasta que esté en `master` con pruebas aprobadas.

**P0 — Seguridad auténtica:** completar E09–E13 con identidad real y recursos externos de bajo riesgo bajo una política `default deny` y no-bypass demostrado en cada entorno compatible; después E14–E15 con evidencias corroboradas por backend y recuperación correcta.

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
