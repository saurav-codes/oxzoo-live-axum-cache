CREATE TABLE entries (
    key text PRIMARY KEY CHECK (key ~ '^[a-z0-9-]{1,64}$'),
    value text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hops (
    trace uuid NOT NULL,
    step text NOT NULL,
    detail text NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (trace, step)
);

CREATE TABLE zoo_probe (
    id bigserial PRIMARY KEY,
    token text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO entries (key, value) VALUES
    ('zoo', 'The oxzoo-live fleet: many stacks on four servers, one ox control plane.'),
    ('axum', 'Axum 0.8 on Tokio, sqlx for Postgres, redis-rs for the cache.'),
    ('ox', 'ox builds from git, runs each process under systemd, and provides the services.');
