# Validación comercial de FARADAY

**Estado:** no hay en el repositorio evidencia acreditada de design partners, pilotos comerciales ni ingresos atribuibles. La ausencia de evidencia pública no descarta conversaciones o acuerdos privados. Este documento es un protocolo de trabajo, no un registro de entrevistas realizadas.

## Hipótesis iniciales

- Comprador a explorar: responsable de seguridad de plataforma o de agentes de una organización que ya use herramientas MCP o agentes con acceso a sistemas internos. Validar quién decide, quién opera y quién paga; no asumir que coinciden.
- Problema a contrastar: dificultad para inventariar llamadas de agentes, controlar accesos y reconstruir decisiones cuando las herramientas se integran por múltiples rutas.
- Alternativas a contrastar: controles del proveedor, gateway existente, políticas de plataforma, revisión manual o no hacer nada. Preguntar por costes y limitaciones reales, no solo por interés en FARADAY.
- Alcance demostrable hoy: preview local, observación opt-in y pilotos sintéticos. No prometer SSO, aislamiento multi-tenant, compliance, no-bypass universal ni operación productiva.

## Entrevistas

Solicitar permiso para tomar notas y explicar su uso; no grabar ni citar a nadie sin consentimiento explícito. Guardar nombres, contactos y notas identificables en un sistema privado aprobado por la organización, con acceso, retención y borrado definidos. En el repositorio solo mantener agregados autorizados, sin credenciales, datos internos o información personal.

Guion de 30 minutos, con preguntas abiertas:

1. ¿Qué agentes y herramientas usan actualmente, quién es responsable y cuál fue el último cambio de acceso que gestionaron?
2. Describa el último incidente, auditoría o revisión de permisos relevante: ¿qué pasó y cómo se resolvió?
3. ¿Cuánto tiempo empleó cada equipo, con qué frecuencia ocurre y qué coste o retraso puede atribuirse? ¿Qué evidencia lo respalda?
4. ¿Qué controles y productos usan hoy? ¿Qué funciona y qué no pueden cubrir, incluidas rutas directas?
5. ¿Quién participa en la decisión, qué requisitos bloquean una prueba y qué alternativa compite por presupuesto?
6. ¿Qué resultado medible justificaría un piloto y qué datos o infraestructura estarían autorizados? ¿En qué plazo?
7. Si el resultado se logra y los requisitos de seguridad se cumplen, ¿cuál sería el proceso real de compra y el rango presupuestario disponible?

Registrar después: segmento y rol seudonimizados, fecha, consentimiento, problema descrito con palabras del participante, frecuencia, medida y fuente, alternativa actual, decisor, objeciones, siguiente paso acordado y fecha. Separar hechos observados, estimaciones e hipótesis; no interpretar cortesía o una reunión como intención de compra.

## Tres design partners

Identificar tres organizaciones distintas y obtener para cada una un responsable con disponibilidad, caso de uso, objetivos, límites y calendario acordados. La participación debe ser voluntaria y documentada; una lista de prospectos no equivale a tres partners. Proponer un correo individual sin enviarlo automáticamente:

> Hola, [nombre]. Estamos investigando cómo los equipos controlan y auditan el acceso de agentes a herramientas. ¿Dispondrías de 30 minutos para contar cómo lo resolvéis hoy y qué dificultades encontráis? No necesitamos datos sensibles ni acceso a vuestros sistemas. Con tu permiso tomaríamos notas privadas para orientar la investigación.

## Piloto con medición

Antes de comenzar, acordar por escrito patrocinador, propietario técnico, duración, alcance, consentimiento, entorno aislado, datos sintéticos, controles de seguridad, plan de salida y responsables de costes. El preview actual no autoriza datos productivos; cualquier ampliación necesita una evaluación y autorización separadas.

Definir un escenario comparable antes/después, muestra, método, persona que recoge los datos y umbrales **acordados con el partner antes de medir**. Como mínimo medir tiempo y esfuerzo para inventariar una integración y revisar cambios, proporción de rutas conocidas realmente observadas, errores o interrupciones y horas de operación. Registrar todas las rutas fuera de cobertura; no interpretar la ausencia de eventos como ausencia de ataques. Añadir coste de infraestructura y personas cuando exista medición fiable. Recoger baseline y resultado con fechas, incertidumbre y limitaciones; no convertir métricas sintéticas en ahorro de cliente.

Para acreditar intención de compra, conservar en el sistema privado evidencia verificable y autorizada del decisor: presupuesto, alcance y plazo, con una carta de intención o proceso de compra documentado si procede. Distinguir compromiso no vinculante, propuesta, contrato firmado e ingreso efectivamente cobrado. No publicar términos, nombre ni documento sin permiso.

## Decisión

Tras las entrevistas y al menos un piloto, revisar: recurrencia y gravedad del problema, existencia de un comprador, valor medido frente a la alternativa, bloqueos de seguridad, coste operativo y señal de presupuesto. Continuar, cambiar hipótesis o detenerse con motivos y evidencia. Tres design partners, un piloto medido y evidencia de intención de compra son metas pendientes, no resultados conseguidos.