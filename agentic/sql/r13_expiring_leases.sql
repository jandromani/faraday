-- R13/lease protocol: run AFTER R12 and only as trusted PostgreSQL administrator.
ALTER TABLE public.faraday_r5_leases ADD COLUMN IF NOT EXISTS lease_until timestamptz;
CREATE OR REPLACE FUNCTION faraday_secure.claim_lease(p_scope text,p_owner text,p_ttl_ms integer)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prev_owner text; prev_epoch bigint; expires timestamptz; next_epoch bigint;
BEGIN
 IF p_scope<>'invoice:demo' OR p_owner !~ '^gateway-[a-z0-9-]{1,30}$'
  OR p_ttl_ms<250 OR p_ttl_ms>30000 THEN
  RAISE EXCEPTION 'invalid lease' USING ERRCODE='22023';
 END IF;
 LOOP
  SELECT owner,epoch,lease_until INTO prev_owner,prev_epoch,expires
  FROM public.faraday_r5_leases WHERE scope=p_scope FOR UPDATE;
  IF NOT FOUND THEN
   INSERT INTO public.faraday_r5_leases(scope,owner,epoch,lease_until)
   VALUES(p_scope,p_owner,1,clock_timestamp()+make_interval(secs=>p_ttl_ms/1000.0))
   ON CONFLICT(scope) DO NOTHING RETURNING epoch INTO next_epoch;
   IF FOUND THEN RETURN next_epoch; END IF;
  ELSIF expires IS NULL OR expires <= clock_timestamp() THEN
   UPDATE public.faraday_r5_leases
   SET owner=p_owner,epoch=prev_epoch+1,
       lease_until=clock_timestamp()+make_interval(secs=>p_ttl_ms/1000.0)
   WHERE scope=p_scope RETURNING epoch INTO next_epoch;
   RETURN next_epoch;
  ELSIF prev_owner=p_owner THEN
   UPDATE public.faraday_r5_leases
   SET lease_until=clock_timestamp()+make_interval(secs=>p_ttl_ms/1000.0)
   WHERE scope=p_scope RETURNING epoch INTO next_epoch;
   RETURN next_epoch;
  ELSE
   RETURN NULL;
  END IF;
 END LOOP;
END$$;
-- Executor still has no privilege to call claim_lease.
-- Retire pre-R13 operator promotion: it creates indefinite legacy epochs.
REVOKE EXECUTE ON FUNCTION faraday_secure.promote(text,text) FROM faraday_controller;
REVOKE ALL ON FUNCTION faraday_secure.claim_lease(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION faraday_secure.claim_lease(text,text,integer) TO faraday_controller;
-- Rebind effects to active, UNEXPIRED lease; no stale process can keep writing.
-- R13 intentionally rejects legacy rows with NULL lease expiry. Any existing
-- leader must reclaim through claim_lease before an effect is accepted.
CREATE OR REPLACE FUNCTION faraday_secure.apply_effect(
 p_scope text,p_owner text,p_epoch bigint,p_operation text,p_digest text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE active_epoch bigint; inserted_count integer; prior text;
BEGIN
 IF p_scope<>'invoice:demo' OR p_owner !~ '^gateway-[a-z0-9-]{1,30}$'
  OR p_epoch<1 OR p_operation !~ '^[-_a-zA-Z0-9]{20,128}$'
  OR p_digest !~ '^[a-f0-9]{64}$' THEN RETURN 'invalid'; END IF;
 SELECT epoch INTO active_epoch FROM public.faraday_r5_leases
 WHERE scope=p_scope AND owner=p_owner AND epoch=p_epoch
   AND lease_until IS NOT NULL AND lease_until>clock_timestamp()
 FOR UPDATE;
 IF NOT FOUND THEN RETURN 'fenced'; END IF;
 INSERT INTO public.faraday_r5_effects(scope,operation_id,payload_hash,epoch)
 VALUES(p_scope,p_operation,p_digest,p_epoch)
 ON CONFLICT(scope,operation_id) DO NOTHING;
 GET DIAGNOSTICS inserted_count=ROW_COUNT;
 IF inserted_count=1 THEN RETURN 'applied'; END IF;
 SELECT payload_hash INTO prior FROM public.faraday_r5_effects
 WHERE scope=p_scope AND operation_id=p_operation;
 IF prior=p_digest THEN RETURN 'duplicate'; END IF;
 RETURN 'conflict';
END$$;
REVOKE ALL ON FUNCTION faraday_secure.apply_effect(text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION faraday_secure.apply_effect(text,text,bigint,text,text) TO faraday_executor;
