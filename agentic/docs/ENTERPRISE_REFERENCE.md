# Referencia empresarial: diseño y brechas

**Estado: diseño propuesto, no entorno empresarial desplegado ni acreditado.** No usar el piloto sintético con datos, credenciales o herramientas productivas. Este documento no otorga SLA, certificación, aislamiento multi-tenant ni aprobación de seguridad.

## Fronteras previstas

El diseño objetivo separa cliente y agente, gateway, proveedor de identidad, gestor de secretos, backend MCP, telemetría y almacenamiento de recuperación. Un terminador TLS administrado debería autenticar las conexiones apropiadas y remitir únicamente tráfico autorizado al gateway; el acceso directo al backend y al gestor de secretos debe bloquearse y probarse en cada despliegue. Los secretos y claves requieren custodios independientes, cifrado, rotación y revocación verificadas. La telemetría debe excluir credenciales y contenido sensible, y contar con acceso y retención definidos. Ninguno de estos servicios externos se proporciona ni se ha validado aquí.

La referencia ejecutable actual es `npm run pilot:docker`, desde `agentic`, en un host POSIX no root con Docker Compose y daemon disponible. Solo crea un piloto sintético efímero. El Compose usa redes separadas para agente y backend, pero la configuración actual del piloto admite HTTP interno y archivos de secretos montados; no es un despliegue con TLS, Vault real o IdP. El perfil adversario prueba rutas seleccionadas, no todo el host o la red. En el entorno local actual el daemon Docker no estaba disponible y la configuración actual no se ha ejecutado. Ver [piloto y límites](V095_SECURE_PILOT.md).

La prueba local `node --test --test-name-pattern="E31 synthetic" tests/mcp-oauth-resource.test.js` integra un token firmado de fixture y JWKS fijo, un servidor HTTP que simula Vault KV v2, gateway y backend en loopback, eventos y backup firmado. Comprueba audiencia incorrecta, fallo de secretos sin gasto de capacidad, ejecución sintética, replay denegado y restauración del journal a una ruta nueva sin reejecución. No despliega un IdP ni Vault, no verifica TLS, aislamiento de red, multitenancy ni operaciones reales. Los eventos son callbacks locales, no un sistema de observabilidad desplegado; el backup solo incluye el journal y no permite reanudar ejecución por sí solo.

## Criterios de aceptación pendientes

Definir antes del piloto las versiones, topología, responsables, amenazas, umbrales, ventanas de observación y ubicación de evidencia. Cada prueba debe identificar el entorno y commit exactos, conservar resultado y fallos, y evitar credenciales o datos de cliente en los informes.

| Control | Evidencia necesaria para ese despliegue |
| --- | --- |
| `idp-sso` | IdP real, login y ciclo de sesión, audiencias y scopes, expiración y revocación probados. |
| `workload-identity` | Identidad de carga atestada, custodia de claves y baja de identidad verificadas. |
| `tenant-isolation` | Aislamiento negativo entre organizaciones para datos, claves, políticas, cuotas, logs y backups. Los mapas estáticos locales no lo demuestran. |
| `secrets-lifecycle` | Gestor real con identidad, mínimo privilegio, emisión, rotación, revocación y pruebas de acceso indebido. |
| `tls` | TLS validado extremo a extremo donde corresponda, confianza y renovación de certificados, y pruebas de certificados inválidos. |
| `observability` | Logs y métricas protegidos, alarmas entregadas y comprobadas, acceso, retención y respuesta a incidentes. |
| `backup-recovery` | Backup cifrado y restauración coordinada de todos los almacenes y claves necesarios; RPO/RTO medidos. |
| `ha-sla` | Objetivos acordados y fallos de componentes probados con recuperación y disponibilidad medidas. |
| `deployment-isolation` | Prueba del entorno real contra acceso directo, egress, secretos y rutas alternativas; incluir controles positivos. |
| `adversarial-testing` | Campaña reproducible sobre el despliegue concreto con permisos y alcance explícitos. |
| `independent-review` | Revisión externa identificada, alcance, hallazgos, remediaciones y evidencia de cierre. |
| `data-governance` | Clasificación, minimización, residencia, cifrado, retención, borrado y controles de acceso acordados. |

`evaluateEnterpriseReference` de `@faraday/agentic/evidence` registra para un commit las declaraciones `pass`, `fail` o `gap` por control. Todo control ausente queda `gap`; una declaración `pass` requiere SHA-256 de evidencia. No lee ni verifica esa evidencia ni prueba que corresponda al commit o despliegue. Siempre conserva el bloqueo `control-evidence-not-verified` y `enterpriseReady: false`, incluso si todas las declaraciones son positivas. No sustituye a `evaluateAssurance`, a una revisión independiente ni a las pruebas anteriores.

```js
import {evaluateEnterpriseReference} from '@faraday/agentic/evidence';
const report=evaluateEnterpriseReference({commit:'a'.repeat(40),checks:[]});
```

No se deben adjuntar a GitHub credenciales, informes privados de terceros ni datos de clientes. Mantener la evidencia en un repositorio controlado y compartir solo referencias o digests cuando exista autorización.