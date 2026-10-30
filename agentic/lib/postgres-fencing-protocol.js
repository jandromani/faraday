/** R5/PostgreSQL reference fencing protocol.
 * Persistence/serialization live inside shared PostgreSQL, not SQLite.
 * NOT multi-region HA and NOT permission for agents to run SQL.
 */
export const R5_FENCING_SCHEMA=String.raw`
CREATE TABLE IF NOT EXISTS faraday_r5_leases (
  scope TEXT PRIMARY KEY CHECK (length(scope) BETWEEN 1 AND 100),
  epoch BIGINT NOT NULL CHECK (epoch > 0),
  owner TEXT NOT NULL CHECK (length(owner) BETWEEN 1 AND 100)
);
CREATE TABLE IF NOT EXISTS faraday_r5_effects (
  scope TEXT NOT NULL REFERENCES faraday_r5_leases(scope),
  operation_id TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  epoch BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope,operation_id)
);
`;
/** psql colon-quoted variable substitutions escape SQL literals. */
export const R5_TAKEOVER_SQL=String.raw`
INSERT INTO faraday_r5_leases(scope,epoch,owner)
VALUES (:'scope',1,:'owner')
ON CONFLICT(scope) DO UPDATE
 SET epoch=faraday_r5_leases.epoch+1,owner=EXCLUDED.owner
RETURNING epoch;
`;
/** Lock guard and effect insert are one PostgreSQL statement.
 * A duplicate represents the same idempotency key AND identical payload.
 */
export const R5_APPLY_SQL=String.raw`
WITH guard AS MATERIALIZED (
 SELECT epoch FROM faraday_r5_leases
 WHERE scope=:'scope' AND owner=:'owner' AND epoch=(:'epoch')::bigint
 FOR UPDATE
), attempt AS (
 INSERT INTO faraday_r5_effects(scope,operation_id,payload_hash,epoch)
 SELECT :'scope',:'operation',:'digest',guard.epoch FROM guard
 ON CONFLICT(scope,operation_id) DO NOTHING RETURNING operation_id
)
SELECT CASE
 WHEN NOT EXISTS(SELECT 1 FROM guard) THEN 'fenced'
 WHEN EXISTS(SELECT 1 FROM attempt) THEN 'applied'
 WHEN EXISTS(SELECT 1 FROM faraday_r5_effects
  WHERE scope=:'scope' AND operation_id=:'operation' AND payload_hash=:'digest') THEN 'duplicate'
 ELSE 'conflict' END;
`;
export const R5_COUNT_SQL=String.raw`
SELECT COUNT(*) AS effects FROM faraday_r5_effects WHERE scope=:'scope';
`;
