# FARADAY — Estado verificado del roadmap (32 épicas)

## E01 y E02: refuerzo local

- E01: modelo STRIDE interno para tres topologías, 13 riesgos priorizados y tres árboles de ataque, con controles existentes, responsables por función, pruebas y controles obligatorios pendientes. No hay personas asignadas ni revisión independiente; los tests no prueban cada despliegue. Ver [modelo de amenazas](../agentic/docs/THREAT_MODEL.md).
- E02: [ADR-001](../agentic/docs/ADR-001-FOUR-COMPONENTS.md) documenta ownership propuesto, dependencias reales, versiones de formatos y gates para separar componentes. Las pruebas ejercitan las cuatro fachadas y la relación firmada Authority→Evidence; el verificador rechaza esquemas de recibo v1 incompatibles aunque tengan firma válida. Son pruebas locales de preview, no una matriz de versiones ni servicios aislados.
## v0.99.7 — E16: signed single-node journal recovery (CI pending)

- SQLite online snapshot, Ed25519 manifest, SHA-256, integrity verification and restore exclusively to a new location.
- Local tampering, overwrite, symbolic link and CLI tests; never re-executes a tool.
- External CI and DR remain pending: no HA, encryption, offsite backups, validated RPO/RTO or independent verification.
- E14/E16/E28 are improved partially, enterprise epics remain open.


## Actualización v0.99.5 — revocación, rotación y evidencias testificadas (2026-10-29)

- **E09/E10:** `LocalOAuthRevocations` opt-in por `jti`, `sub` y `client_id`, SQLite persistente y comprobación efectiva por solicitud HTTP; ausencia de `jti` o fallo del registro deniega. `PinnedOAuthResource.replacePublicJwks` sustituye de forma atómica un conjunto validado de claves **cuando un operador invoca la API**. Sin IdP ni revocación distribuida.
- **E12:** lectura estricta de secreto de backend mediante archivos 0600 re-leídos por gateway y backend. Test end-to-end demuestra discrepancia de credenciales → denegación y estado incierto, replay impedido, y una capacidad nueva funciona tras rotación sin reiniciar. **No hay Vault, KMS ni broker de credenciales efímeras.**
- **E14:** nuevo checkpoint de recibos de gateway y atestaciones de backend sintéticas, cadena de digests y firma de testigo Ed25519 con raíz de confianza suministrada aparte. Comprueba adulteración/reordenación/truncado y opcionalmente raíz esperada para detectar replay de checkpoints antiguos. **No existe aún testigo independiente integrado ni custodia offsite real.**
- **E15/E16:** prueba integrada de rotación equivocada y no-replay de capacidades; no es HA, failover, ni reconciliación distribuida.
- **Calidad:** suite Node local original ampliada a 243 pruebas antes del último test E2E de recuperación; CI adicional `trust-controls.yml` en Linux Node 22/24, macOS 24 y Windows 24. Su aprobación se registra separadamente en Actions.
- **Clasificación:** todos son **avances parciales de Developer Preview**. Ninguna de las 32 épicas originales se cierra con este cambio y no se alteran cifras VC sin evidencia externa. Documentación: `agentic/docs/V0995_TRUST_HARDENING.md`.

## Auditoría local posterior a v0.99.4 (2026-10-29)

- `npm run test:all` completado en Windows y Node 24.22.0: 232 pruebas Node aprobadas, 11 omitidas; 6 pruebas Python aprobadas, 2 omitidas. Las omisiones incluyen limitaciones de ACL y enlaces simbólicos en Windows, no cuentan como pruebas aprobadas.
- Los 200 casos OAuth firmados son sintéticos y locales. El laboratorio mantiene 650 comprobaciones aprobadas y 350 brechas; `lab:gate` bloquea por esas brechas. El informe de aceptación acotada marca 14/15, con E05 bloqueada por protección ACL no verificada en Windows. Ninguna de las 32 épicas originales se declara cerrada.
- La auditoría npm en seco inventarió 115 archivos sin hallazgos de sus reglas locales; no es un escaneo integral del repositorio ni una certificación. La configuración Docker se validó sintácticamente, pero el daemon no estaba disponible y no se ejecutó el aislamiento actualizado.
- Estas pruebas corresponden al árbol de trabajo local, no a una CI multiplataforma ni a una auditoría independiente. Siguen pendientes identidad y aislamiento reales, alta disponibilidad, validación externa y pilotos comerciales.

## Cambios locales posteriores a v0.99.4

- E01/E02: modelo de amenazas y recorrido del piloto aclarados en `agentic/SECURITY.md` y ADR-001. Son documentación interna, no revisión independiente ni servicios separados.
- E03/E04/E05: el instalador automático rechaza Windows antes de crear backups mientras no se verifiquen sus ACL; `dry-run` y desinstalación siguen disponibles. Revisar y proteger manualmente backups existentes. La auditoría local marca ACL desconocidas y exploraciones incompletas como revisión; la CLI devuelve código no cero ante fallos o revisiones pendientes. `graph prune` permite previsualizar y eliminar explícitamente eventos anteriores a una fecha; no elimina agregados, otros almacenes o backups, ni garantiza borrado físico.
- E03/E04: Shield admite una lista optativa de métodos MCP para tráfico cliente-servidor mediado; TrustDiff detecta su ampliación o retirada. Una prueba HTTP local demuestra que el acceso directo al backend sigue eludiendo el puente. `graph clear` previsualiza o elimina transaccionalmente las cuatro tablas conocidas del grafo y su índice de importación de adaptadores, si existe, con confirmación explícita: no cubre otras tablas, WAL, copias, exports ni borrado físico o por organización. Quedan pendientes aislamiento obligatorio, ACL verificadas, cifrado, política integral de retención y separación entre organizaciones.
- E05/E06: las nuevas instalaciones registran el wrapper completo y el rollback rechaza cambios; backups antiguos conservan una comprobación parcial por compatibilidad. El puente correlaciona respuestas HTTP y SSE, rechaza eventos truncados o respuestas ajenas, evita respuestas terminales duplicadas y transmite errores HTTP JSON-RPC correlacionables sin reintentar. Las pruebas HTTP son locales y sintéticas; la evidencia oficial previa es stdio y anterior al bloqueo de instalación en Windows. Siguen pendientes ACL, instalación/upgrade/rollback con usuarios reales, conformidad HTTP independiente, OAuth completo, MRTR y reanudación SSE legacy.
- E07/E08: la ingestión nueva distingue denegaciones, inicios y observaciones no verificadas de llamadas completadas declaradas; el hook OpenAI no declara éxito por un resultado opaco. El observador descarta ciclos de cursores y el borrado del grafo elimina el índice de deduplicación para permitir reimportaciones. Los registros anteriores no se migran. Siguen pendientes agentes reales con delegación y herramientas externas, identidad propagada y unión causal verificable entre autorización, backend y recibo.
- E09/E10: `NonceLedger` incorpora revocación persistente local de agente, emisor y capacidad, comprobada en la transacción de consumo. Se prueban revocación durante espera externa y replay entre procesos; reglas mal formadas y relojes inválidos fallan cerrados. No hay propagación entre ledgers, cancelación de operaciones ya autorizadas, servicio administrativo autenticado, attestation, delegación interagentes ni tenancy. [Alcance](../agentic/docs/V09_AUTHORITY_PREVIEW.md).
- E06–E10: el puente HTTP usa la versión confirmada por la inicialización JSON/SSE; no implica conformidad MCP completa. El observador correlaciona cursores y descarta listados parciales erróneos o solapados; esto no acredita causalidad completa. Los tres adaptadores se prueban entre Python y Node con SDKs simulados, no con frameworks reales. Una discrepancia OAuth se rechaza antes de gastar la capacidad y la política se vuelve a evaluar tras la espera externa; las claves fijadas no son identidad atestada ni el filtro es un gateway obligatorio.
- E11–E15: el piloto exige HTTPS para el backend no local salvo excepción explícita; Docker sintético usa esa excepción y no cifra el tráfico. El Compose configura límites adicionales para gateway y agente, pendientes de prueba con Docker. El lector opcional Vault KV v2 consulta cada solicitud y falla cerrado, probado solo con un servidor simulado; la rotación del backend y el ciclo del token no se gestionan. Las pruebas locales impiden redirecciones con credenciales y demuestran que un atacante con la credencial y ruta directa elude el gateway. No hay gateway obligatorio universal, Vault real validado, KMS, sandbox de producción ni prueba de efectos externos. Las respuestas sin evidencia verificada quedan inciertas y se reconcilian sin repetir la operación; la firma del recibo exige base64url canónico.
- E13/E14: se añade un perfil Docker con herramienta hostil sintética, control de conectividad y pruebas de rutas por IP, filesystem, secretos concretos y privilegios; la configuración actual no se ha ejecutado sin daemon Docker. Los recibos simulados exigen claves distintas de gateway y backend. Hay checkpoints offline con una tercera firma y ancla de prefijo proporcionada por el operador; no son un testigo externo, almacenamiento inmutable, hora confiable ni evidencia de efectos reales. [Límites](../agentic/docs/V0951_EVIDENCE_RECOVERY.md).
- E15/E16: se prueban caída real del proceso del gateway tras una operación sintética, conciliaciones concurrentes y deduplicación entre procesos sobre un único SQLite. El backup online del journal se firma, verifica y restaura a una ruta nueva; un pin externo opcional detecta la sustitución por otro digest. No incluye nonces, revocaciones ni backend: no se debe reanudar ejecución con el journal restaurado aislado. No hay deduplicación multinodo, compensación real, failover ni RPO/RTO medidos. [Operación y límites](../agentic/docs/V0951_EVIDENCE_RECOVERY.md).
- E17/E18: un SQLite local aplica cuotas de llamadas por agente y organización configurada estáticamente, con pruebas entre procesos y rollback conjunto. El gateway exige que la clave del agente no cuente para el quorum y guarda las firmas verificadas en la reserva del journal, también en backups. Las claves y roles no acreditan personas ni tenants; la evidencia no es inmutable ni está vinculada al recibo firmado. Faltan contadores distribuidos, medición de recursos o tokens, alertas, identidad/SSO, bandeja y rechazo o cancelación operativos. [Operación y límites](../agentic/docs/V096_SECURITY_OPERATIONS.md).
- E19: cuarentena, evento y cola de alerta se guardan transaccionalmente; la CLI puede enviar alertas HTTPS explícitamente y ofrece recuperación condicionada a la cabecera revisada de la cadena. Pruebas locales cubren procesos concurrentes, fallo de escritura y reenvío duplicado; el transporte externo solo se simula. No hay SIEM real, entrega automática, identidad de operador, evidencia inmutable ni bloqueo multinodo; `resume` conserva la vía sin revisión por compatibilidad. [Operación y límites](../agentic/docs/V096_SECURITY_OPERATIONS.md).
- E20/E21: preflight compara offline decisiones declaradas con la implementación `ToolPolicy` y una prueba observa un puente HTTP con backend sintético local. TimeMachine añade firma Ed25519 de trazas sintéticas y pin opcional suministrado por el operador. Los archivos de observaciones pueden contener argumentos sensibles; no se capturan ni autentican automáticamente. No hay captura de workflows reales, causalidad, custodia independiente ni testigo externo. [Operación y límites](../agentic/docs/V097_TIMEMACHINE_RECOVERY.md).
- E22: MemoryGuard local incorpora documentos firmados con fuentes configuradas, cuarentena por defecto, revisión explícita y comprobación de contradicciones entre hechos estructurados exactos; un corpus sintético cubre suplantación, alteración, instrucciones hostiles y concurrencia local. La firma no demuestra que el contenido sea seguro, la revisión no autentica personas y el componente no está conectado al asesor ni a RAG. [Operación y límites](../agentic/docs/MEMORY_GUARD_PREVIEW.md).
- E23/E24: campañas offline separadas coordinan roles programados, memoria firmada y gateway/backend MCP sintéticos en loopback; incluyen fallos seleccionables, replay y una secuencia reactiva de ataques prefijados con comprobación de efectos y recibos. No son agentes autónomos ni atacante independiente; hay una sola identidad de agente y ninguna delegación criptográfica, aislamiento fuerte o red team externo. El corpus original conserva sus 350 GAP. [Alcance y ejecución](../agentic/docs/LAB_CAMPAIGNS_PREVIEW.md).
- E25–E27: cliente JavaScript MCP oficial 1.32.2 y servidor filesystem 2.0.1 probados localmente en Windows mediante el proxy stdio, con lectura y registro del contrato; la matriz CI nueva está pendiente de ejecución. Las mutaciones miden cobertura en dos módulos y una prueba corta un socket después del efecto sintético; no hay fuzzing guiado, reproducción exacta de crashes ni chaos distribuido. Un benchmark concurrente en loopback informa p50/p95/p99, throughput, errores, CPU/RSS del proceso y un control negativo; no hay baseline comparable, carga externa ni coste operativo. [Compatibilidad](../agentic/docs/COMPATIBILITY.md) y [mediciones y límites](../agentic/docs/LAB_CAMPAIGNS_PREVIEW.md).
- E28–E30: una firma offline Ed25519 vincula los bytes de un tarball y un inventario a identidad declarada, con clave pública fijada externamente; se prueba con un paquete npm local. No verifica que el inventario describa el tarball ni aporta dependencias resueltas, provenance o publicación. El visor puede inspeccionar un journal seleccionado al inicio, sin modificarlo ni ofrecer RBAC. El smoke Windows comprueba instalación offline del paquete, previsualización y rechazo de instrumentación automática sin cambios ni backup: no habilita esa instalación. Siguen pendientes protección remota, release firmada, consola autenticada y onboarding externo. [Alcance de firma](../agentic/docs/RELEASE_EVIDENCE_PREVIEW.md).
- E31/E32: se documentan un diseño de referencia y criterios de aceptación, una prueba integrada sintética y un protocolo para entrevistas, partners y piloto medido. El evaluador declara controles ausentes como GAP y nunca afirma preparación empresarial; IdP, Vault real, TLS, HA, multi-tenancy y revisión independiente siguen sin verificarse. No se han acreditado design partners, pilotos o intención de compra. [Referencia](../agentic/docs/ENTERPRISE_REFERENCE.md) y [validación comercial](COMMERCIAL_VALIDATION.md).
- E16–E21: el inspector señala fechas futuras sin reejecutar reservas; la cuota local rechaza retrocesos respecto al último consumo aceptado; quorum requiere claves Ed25519 distintas; parada y auditoría Sentinel son atómicas; TrustDiff compara antes de redactar y TimeMachine rechaza entradas parciales. Siguen sin existir failover distribuido, aislamiento por tenant, aprobación humana/SSO, SIEM/HA, causalidad real ni replay de workflows reales.
- Evidencia: el informe de gates no considera aprobados tests TAP omitidos. E05 queda bloqueada en Windows hasta implementar y verificar protección de ACL. Los cambios siguen locales y no sustituyen la regresión completa, CI multiplataforma ni auditoría independiente.

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
- **E21:** `agentic/lib/timemachine.js` ofrece replay offline sintético y checkpoint local opcional firmado. **No hay captura real de workflows ni testigo externo; la firma no acredita procedencia independiente.**
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
| E09 | Agent identity / delegation | Parcial | G: claves Ed25519 fijadas, prueba de posesión y revocación persistente local | SPIFFE/OIDC real, attestation, delegación interagentes y revocación distribuida |
| E10 | Authority / policy engine | Parcial | G: capacidades firmadas, políticas estrictas y ledger local; L: validación en MCP protegido | Motor general de políticas, múltiples recursos/tenants y gestión distribuida |
| E11 | Mandatory gateway / no bypass | Parcial | G: prueba Docker de separación de redes v0.9; L: MCP protegido y bypass local demostrado con credencial | Agente y MCP externos, red segmentada real, rutas directas y credenciales generales |
| E12 | Secrets broker | Parcial | G: credencial sintética backend solo en gateway; L: lector KV v2 optativo probado con servidor simulado | Vault real/KMS, emisión efímera, rotación integral, revocación, aislamiento por tenant y pruebas de exfiltración reales |
| E13 | FARADAY Enclave | Parcial | G: aislamiento de red Docker histórico; L: perfil de herramienta hostil sintética aún sin ejecutar | Docker actualizado, MCP no confiables reales, egress, sandbox, tenancy, attestation |
| E14 | Verifiable receipts | Parcial **G** | G: recibo y attestation sintética Ed25519; L: checkpoint offline con tercera clave y prefijo confiable | Testigo y ancla externos, KMS, ciclo de claves y prueba independiente de efectos reales |
| E15 | Idempotency / semantics | Parcial **G** | G: SQLite backend idempotente; L: caída de proceso y concurrencia sobre un único SQLite | HA, deduplicación multinodo, herramientas reales y compensación |
| E16 | High availability / recovery | Parcial **G** | G: inspector SQLite read-only; L: backup online firmado y restauración en ruta nueva, solo journal | Failover, recuperación coordinada de todos los almacenes, multinodo, RPO/RTO y caos de producción |
| E17 | Resource / cost governance | Parcial | G v0.96: cuotas por agente; L: cuota agregada local por organización configurada y pruebas entre procesos | Límites distribuidos por tenant/CPU/tokens, identidad e aislamiento, alertas y medición real |
| E18 | Human approval / governance | Parcial | G v0.96: firmas offline, quorum, roles y alcance; L: claves distintas del agente y evidencia en journal | Humanos/identidad empresarial verificados, UI, rechazo/cancelación y evidencia inmutable |
| E19 | Sentinel / incident response | Parcial | G v0.96: parada y cuarentena locales; L: cola HTTPS explícita, recuperación con cabecera revisada y pruebas entre procesos locales | SIEM real, entrega automática, operadores autenticados, bloqueo multinodo y evidencias ancladas externamente |
| E20 | Preflight / impact engine | Parcial | G: Contracts y TrustDiff; L: simulación ToolPolicy con observaciones declaradas y prueba de puente local sintético | Autoridad de recursos, observaciones autenticadas, impacto causal y pruebas generadas por riesgo |
| E21 | TimeMachine | Parcial **G** | G v0.97: replay sintético; L: checkpoint firmado y pin opcional de traza sintética | Captura de workloads reales, cifrado, procedencia independiente, causalidad y replay de workflows |
| E22 | MemoryGuard / free AI | Parcial | G: asesor `free` opcional; L: cuarentena SQLite, fuentes firmadas, revisión local y corpus sintético | Integración RAG obligatoria, identidad y procedencia independientes, contradicción semántica, evaluación real y auditoría inmutable |
| E23 | Dummy agent factory | Parcial | G: 12 actores y servidor MCP sintético; L: roles programados con memoria y gateway sintéticos | Agentes autónomos reales, delegación autenticada, reloj/red controlados y herramientas externas |
| E24 | Offensive evals | Parcial | G: escenarios deterministas con lagunas explícitas; L: casos MCP criptográficos y campaña reactiva prefijada en loopback | Atacante independiente, exploración abierta, despliegues aislados y red team |
| E25 | Compatibility lab | Parcial **G v0.98** | G: matriz estática y smokes SDK; L: cliente y servidor MCP oficiales a través del proxy stdio en Windows | Conformidad MCP y workflows completos, matriz versiones/OS ejecutada y clientes IDE reales |
| E26 | Fuzzing / chaos | Parcial | G: 760 mutaciones deterministas; L: cobertura de dos módulos y pérdida de socket tras efecto sintético | Fuzzing guiado, reproducción exacta de crashes, mutación amplia y chaos distribuido |
| E27 | Benchmarks / scoreboard | Parcial **G** | G: microbenchmarks; L: gateway sintético concurrente con percentiles, recursos y control negativo | MCP externos, baseline sin FARADAY, hardware controlado, tasa de falsos permisos, costes y competidores |
| E28 | Secure supply chain | Parcial **G** | G: inventario SPDX por fichero y gate local; L: firma offline de tarball e inventario con clave fijada | Protección de rama, SBOM de dependencias, SLSA, publicación y release verificables |
| E29 | Control Console | Parcial | G: visor local HTTP protegido por token; L: inspección opcional read-only del journal | RBAC e identidad, políticas, approvals, revocaciones y flujo administrativo autenticado |
| E30 | Distribution / DX | Parcial | G: CLI, documentación y paquete privado; L: smoke Windows verifica rechazo seguro y dry-run | Instalación automática Windows con ACL verificadas, release firmada, npm público y quickstart externo |
| E31 | Enterprise readiness | **Pendiente** | L: diseño de referencia, controles declarativos y prueba integrada sintética; no hay SSO o tenancy real | IdP y secretos reales, TLS, HA, SLA, aislamiento, recuperación y seguridad independiente |
| E32 | Commercial validation / launch | **Pendiente** | L: protocolo de entrevistas y medición; no hay partners, pilotos ni ingresos acreditados | Tres design partners, un piloto con valor medido e intención de compra verificable |

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
