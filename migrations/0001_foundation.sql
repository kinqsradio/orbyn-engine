-- Background work. A worker claims a job with FOR UPDATE SKIP LOCKED and holds a
-- lease; a job whose lease runs out goes back to the queue, or fails when it has
-- used all its attempts. The idempotency key, scoped to the job kind, makes
-- enqueueing the same effect twice a no-op.
CREATE TABLE jobs (
    id              uuid        PRIMARY KEY,
    kind            text        NOT NULL,
    payload         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key text,
    state           text        NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued', 'running', 'done', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0,
    max_attempts    integer     NOT NULL DEFAULT 10,
    run_at          timestamptz NOT NULL DEFAULT now(),
    leased_by       text,
    lease_until     timestamptz,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, idempotency_key)
);

CREATE INDEX jobs_ready ON jobs (run_at) WHERE state = 'queued';
CREATE INDEX jobs_leases ON jobs (lease_until) WHERE state = 'running';
