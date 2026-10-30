-- R12: PostgreSQL-native fenced synthetic effects, strict role separation.
-- Applied by a trusted administrator/function-owner only.
-- PRECONDITION: faraday_executor and faraday_controller are distinct LOGIN
-- roles provisioned separately; NEVER pass administrator creds to MCP agents.
CREATE SCHEMA IF NOT EXISTS faraday_secure;
REVOKE ALL ON SCHEMA faraday_secure FROM PUBLIC;
CREATE TABLE IF NOT EXISTS public.faraday_r5_leases (
  scope TEXT PRIMARY KEY CHECK(length(scope) BETWEEN 1 AND 100),
  epoch BIGINT NOT NULL CHECK(epoch>0),
  owner TEXT NOT NULL CHECK(length(owner) BETWEEN 1 AND 100)
);
CREATE TABLE IF NOT EXISTS public.faraday_r5_effects (
  scope TEXT NOT NULL REFERENCES public.faraday_r5_leases(scope),
  operation_id TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  epoch BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(scope,operation_id)
);
REVOKE ALL ON public.faraday_r5_leases,public.faraday_r5_effects FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM faraday_executor,faraday_controller;
CREATE OR REPLACE FUNCTION faraday_secure.promote(p_scope text,p_owner text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE next_epoch bigint;
BEGIN
 IF p_scope<>'invoice:demo' OR p_owner !~ '^gateway-[a-z0-9-]{1,30}$' THEN
  RAISE EXCEPTION 'invalid promotion input' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.faraday_r5_leases(scope,epoch,owner)
 VALUES(p_scope,1,p_owner)
 ON CONFLICT(scope) DO UPDATE SET epoch=public.faraday_r5_leases.epoch+1,owner=excluded.owner
 RETURNING epoch INTO next_epoch;
 RETURN next_epoch;
END$$;
CREATE OR REPLACE FUNCTION faraday_secure.apply_effect(
 p_scope text,p_owner text,p_epoch bigint,p_operation text,p_digest text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE active_epoch bigint; inserted_count integer; prior text;
BEGIN
 IF p_scope<>'invoice:demo' OR p_owner !~ '^gateway-[a-z0-9-]{1,30}$'
  OR p_epoch<1 OR p_operation !~ '^[-_a-zA-Z0-9]{20,128}$'
  OR p_digest !~ '^[a-f0-9]{64}$' THEN RETURN 'invalid'; END IF;
 SELECT epoch INTO active_epoch FROM public.faraday_r5_leases
 WHERE scope=p_scope AND owner=p_owner AND epoch=p_epoch FOR UPDATE;
 IF NOT FOUND THEN RETURN 'fenced'; END IF;
 INSERT INTO public.faraday_r5_effects(scope,operation_id,payload_hash,epoch)
 VALUES(p_scope,p_operation,p_digest,p_epoch)
 ON CONFLICT(scope,operation_id) DO NOTHING;
 GET DIAGNOSTICS inserted_count = ROW_COUNT;
 IF inserted_count=1 THEN RETURN 'applied'; END IF;
 SELECT payload_hash INTO prior FROM public.faraday_r5_effects
 WHERE scope=p_scope AND operation_id=p_operation;
 IF prior=p_digest THEN RETURN 'duplicate'; END IF;
 RETURN 'conflict';
END$$;
CREATE OR REPLACE FUNCTION faraday_secure.lookup_effect(p_scope text,p_operation text)
RETURNS TABLE(payload_hash text,record_state text,occurred_at_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_scope<>'invoice:demo' OR p_operation !~ '^[-_a-zA-Z0-9]{20,128}$'
 THEN RAISE EXCEPTION 'invalid lookup' USING ERRCODE='22023'; END IF;
 RETURN QUERY
 SELECT trim(e.payload_hash)::text,'simulated'::text,
 (extract(epoch from e.created_at)*1000)::bigint
 FROM public.faraday_r5_effects e
 WHERE e.scope=p_scope AND e.operation_id=p_operation;
END$$;
CREATE OR REPLACE FUNCTION faraday_secure.count_effects(p_scope text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n bigint;
BEGIN
 IF p_scope<>'invoice:demo' THEN RAISE EXCEPTION 'invalid scope' USING ERRCODE='22023'; END IF;
 SELECT count(*) INTO n FROM public.faraday_r5_effects WHERE scope=p_scope;
 RETURN n;
END$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA faraday_secure FROM PUBLIC;
GRANT USAGE ON SCHEMA faraday_secure TO faraday_executor,faraday_controller;
GRANT EXECUTE ON FUNCTION faraday_secure.promote(text,text) TO faraday_controller;
GRANT EXECUTE ON FUNCTION faraday_secure.apply_effect(text,text,bigint,text,text) TO faraday_executor;
GRANT EXECUTE ON FUNCTION faraday_secure.lookup_effect(text,text) TO faraday_executor;
GRANT EXECUTE ON FUNCTION faraday_secure.count_effects(text) TO faraday_executor;
