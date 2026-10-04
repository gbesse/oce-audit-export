-- FR : exécuter après la création du rôle par l'administrateur de la base.
-- EN: run after the database administrator creates the role.
-- ES: ejecutar después de que el administrador de la base cree el rol.
GRANT USAGE ON SCHEMA occ TO oce_audit_reader;
GRANT SELECT (id, occurred_at, kind, actor_id, action, namespace_id,
              resource_kind, resource_id, outcome)
ON occ.audit_events TO oce_audit_reader;
