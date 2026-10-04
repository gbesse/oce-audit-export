# OCE Audit Export / Export d’audit / Exportación de auditoría

## Français

Exporteur **opérateur** pour le journal d'audit d'OpenClaw Enterprise (OCE). OCE conserve actuellement ce journal dans PostgreSQL sans API HTTP publique de consultation ou d'export ; son Collector de logs opérationnels ne le prend pas en charge. Cet outil lit uniquement les colonnes nécessaires de `occ.audit_events` avec un rôle SQL dédié, puis écrit du NDJSON privé ou envoie des logs OTLP/HTTP JSON vers un collecteur SIEM. Il ne modifie ni OCE ni sa base. [Limites officielles de l'audit](https://docs-enterprise.openclaw.org/guides/topics/audit-log/) ; [spécification OTLP](https://github.com/open-telemetry/opentelemetry-proto/blob/main/docs/specification.md).

Une API native de consultation est déjà proposée dans le [RFC OCE 37](https://github.com/openclaw/openclaw-enterprise/blob/main/specs/rfcs/37-platform-audit/index.md), encore au statut `Proposed`. Elle exige des décisions IAM et exclut explicitement l'export dans son périmètre actuel. Cet outil ne prétend pas remplacer cette API ni anticiper son autorisation.

Les événements exportés contiennent l'ID d'audit, l'heure, le type, l'action et le résultat. Les identifiants d'acteur, de namespace et de ressource sont remplacés par des références HMAC stables pour une même clé locale. Le champ PostgreSQL `details`, qui peut contenir d'autres métadonnées, n'est **jamais lu**. Les exports restent des données d'opérateur privées. Aucun contenu de prompt, réponse, secret ou message n'est ajouté par l'outil.

Faire créer un rôle PostgreSQL distinct avec `LOGIN` par l'administrateur de la base, puis appliquer les droits limités de `sql/readonly-grants.sql`. Ne pas réutiliser le compte de l'application. Placer son URL `postgres://...` dans un fichier `600`, avec TLS et validation du serveur selon la politique de l'installation. Générer une clé HMAC locale et copier `config.example.json` vers `config.json` (ignoré par Git) :

```sh
node cli.js init-key /secure/path/audit-hmac.key
node cli.js run config.json
```

Pour OTLP, remplacer `sink` par `{ "type": "otlp", "url": "https://collector.example.com/v1/logs" }`. Un fichier optionnel `headersFile` en mode `600` contient des en-têtes JSON d'authentification et doit rester hors Git. Une réponse OTLP partiellement rejetée fait échouer le lot sans avancer le curseur. Les sorties NDJSON sont créées en mode `600`. Un verrou empêche deux processus de partager le même curseur. Les envois sont **au moins une fois** : un arrêt après l'acceptation du lot mais avant l'enregistrement du curseur peut répéter des événements. Dédupliquer par `eventId` dans le SIEM. Le code de sortie `2` signifie que `maxBatches` a été atteint avant la fin.

`npm test` vérifie la pseudonymisation et les échecs OTLP. La CI exécute aussi un test PostgreSQL avec un rôle qui n'a pas le droit de lire `details`. Aucun test local sans `OCE_AUDIT_TEST_DATABASE_URL` ne prouve l'accès à une vraie base OCE. Licence MIT.

## English

An **operator** exporter for the OpenClaw Enterprise (OCE) audit ledger. OCE currently stores this ledger in PostgreSQL without a public HTTP browsing or export API; its operational log Collector does not carry audit events. This tool reads only required columns from `occ.audit_events` using a dedicated SQL role, then writes private NDJSON or sends OTLP/HTTP JSON logs to a SIEM collector. It changes neither OCE nor its database. See the [official audit limits](https://docs-enterprise.openclaw.org/guides/topics/audit-log/) and [OTLP specification](https://github.com/open-telemetry/opentelemetry-proto/blob/main/docs/specification.md).

A native browsing API is already proposed in [OCE RFC 37](https://github.com/openclaw/openclaw-enterprise/blob/main/specs/rfcs/37-platform-audit/index.md), still marked `Proposed`. It requires IAM decisions and explicitly excludes export from its current scope. This tool does not claim to replace that API or preempt its authorization.

Exported events contain the audit ID, timestamp, kind, action, and outcome. Actor, namespace, and resource IDs become stable HMAC references under one local key. PostgreSQL's `details` field, which may carry other metadata, is **never read**. Exports remain private operator data. The tool adds no prompt, response, secret, or message content.

Have the database administrator create a separate PostgreSQL `LOGIN` role and apply the limited grants in `sql/readonly-grants.sql`. Do not reuse the application account. Put its `postgres://...` URL in a `600` file, with TLS and server validation according to your installation policy. Generate a local HMAC key and copy `config.example.json` to `config.json` (Git ignored), then run the commands above.

For OTLP, replace `sink` with `{ "type": "otlp", "url": "https://collector.example.com/v1/logs" }`. An optional `headersFile` with mode `600` contains JSON authentication headers and must stay out of Git. Partial OTLP rejection fails the batch without advancing the cursor. NDJSON files are created with mode `600`. A lock stops two processes from sharing one cursor. Delivery is **at least once**: a crash after batch acceptance but before saving the cursor can repeat events. Deduplicate by `eventId` in the SIEM. Exit code `2` means `maxBatches` was reached before completion.

`npm test` checks pseudonymization and OTLP failures. CI also runs a PostgreSQL test with a role unable to read `details`. Local tests without `OCE_AUDIT_TEST_DATABASE_URL` do not prove access to a real OCE database. MIT licensed.

## Español

Exportador **para operadores** del registro de auditoría de OpenClaw Enterprise (OCE). OCE guarda actualmente este registro en PostgreSQL sin API HTTP pública para consultarlo o exportarlo; su Collector de logs operativos no incluye los eventos de auditoría. La herramienta lee solo las columnas necesarias de `occ.audit_events` con un rol SQL dedicado y escribe NDJSON privado o envía logs OTLP/HTTP JSON a un colector SIEM. No modifica OCE ni su base de datos. Consulta los [límites oficiales de auditoría](https://docs-enterprise.openclaw.org/guides/topics/audit-log/) y la [especificación OTLP](https://github.com/open-telemetry/opentelemetry-proto/blob/main/docs/specification.md).

La API nativa de consulta ya está propuesta en el [RFC OCE 37](https://github.com/openclaw/openclaw-enterprise/blob/main/specs/rfcs/37-platform-audit/index.md), todavía con estado `Proposed`. Requiere decisiones IAM y excluye expresamente la exportación de su alcance actual. Esta herramienta no pretende sustituir esa API ni anticipar su autorización.

Los eventos exportados contienen el ID de auditoría, la fecha, el tipo, la acción y el resultado. Los ID de actor, espacio de nombres y recurso se sustituyen por referencias HMAC estables con una misma clave local. El campo PostgreSQL `details`, que puede contener otros metadatos, **nunca se lee**. Las exportaciones siguen siendo datos privados de operador. La herramienta no añade contenido de prompts, respuestas, secretos ni mensajes.

Pide al administrador de la base que cree un rol PostgreSQL `LOGIN` independiente y aplique los permisos limitados de `sql/readonly-grants.sql`. No reutilices la cuenta de la aplicación. Guarda su URL `postgres://...` en un archivo con permisos `600`, con TLS y validación del servidor según la política de la instalación. Genera una clave HMAC local y copia `config.example.json` a `config.json` (ignorado por Git); ejecuta los comandos anteriores.

Para OTLP, sustituye `sink` por `{ "type": "otlp", "url": "https://collector.example.com/v1/logs" }`. Un archivo opcional `headersFile` con permisos `600` contiene cabeceras JSON de autenticación y debe quedar fuera de Git. Un rechazo parcial de OTLP hace fallar el lote sin avanzar el cursor. Los archivos NDJSON se crean con permisos `600`. Un bloqueo impide que dos procesos compartan un cursor. La entrega es **al menos una vez**: un corte después de aceptar un lote pero antes de guardar el cursor puede repetir eventos. Elimina duplicados por `eventId` en el SIEM. El código de salida `2` indica que se alcanzó `maxBatches` antes de terminar.

`npm test` comprueba la seudonimización y los fallos OTLP. La CI ejecuta además una prueba PostgreSQL con un rol sin permiso para leer `details`. Las pruebas locales sin `OCE_AUDIT_TEST_DATABASE_URL` no demuestran acceso a una base OCE real. Licencia MIT.
