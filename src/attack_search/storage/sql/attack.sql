-- PostgreSQL. All generated data is isolated in the attack schema.
CREATE SCHEMA IF NOT EXISTS attack;

CREATE TABLE IF NOT EXISTS attack.nodes (
    id TEXT PRIMARY KEY,
    attack_id TEXT,
    type TEXT NOT NULL CHECK (type NOT IN ('intrusion-set', 'campaign', 'malware', 'tool', 'relationship')),
    name TEXT,
    description TEXT,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    stix_json JSONB NOT NULL,
    CHECK (split_part(id, '--', 1) = type)
);

CREATE TABLE IF NOT EXISTS attack.relationships (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES attack.nodes(id),
    target_id TEXT NOT NULL REFERENCES attack.nodes(id),
    relationship_type TEXT NOT NULL,
    description TEXT,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    stix_json JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS attack.behavior_examples (
    id BIGINT PRIMARY KEY,
    technique_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (technique_id LIKE 'attack-pattern--%'),
    text TEXT NOT NULL CHECK (length(btrim(text)) > 0)
);

CREATE TABLE IF NOT EXISTS attack.technique_tactics (
    technique_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (technique_id LIKE 'attack-pattern--%'),
    tactic_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (tactic_id LIKE 'x-mitre-tactic--%'),
    PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE IF NOT EXISTS attack.strategy_analytics (
    strategy_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (strategy_id LIKE 'x-mitre-detection-strategy--%'),
    analytic_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (analytic_id LIKE 'x-mitre-analytic--%'),
    PRIMARY KEY (strategy_id, analytic_id)
);

CREATE TABLE IF NOT EXISTS attack.analytic_data_components (
    analytic_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (analytic_id LIKE 'x-mitre-analytic--%'),
    data_component_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (data_component_id LIKE 'x-mitre-data-component--%'),
    PRIMARY KEY (analytic_id, data_component_id)
);

CREATE TABLE IF NOT EXISTS attack.matrix_tactics (
    matrix_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (matrix_id LIKE 'x-mitre-matrix--%'),
    tactic_id TEXT NOT NULL REFERENCES attack.nodes(id)
        CHECK (tactic_id LIKE 'x-mitre-tactic--%'),
    position INTEGER NOT NULL CHECK (position > 0),
    PRIMARY KEY (matrix_id, tactic_id),
    UNIQUE (matrix_id, position)
);

CREATE INDEX IF NOT EXISTS idx_nodes_attack_id ON attack.nodes(attack_id);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON attack.nodes(type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_technique_attack_id ON attack.nodes(attack_id)
    WHERE type = 'attack-pattern';
CREATE INDEX IF NOT EXISTS idx_relationships_source ON attack.relationships(source_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON attack.relationships(target_id, relationship_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_subtechnique_parent ON attack.relationships(source_id)
    WHERE relationship_type = 'subtechnique-of' AND NOT revoked AND NOT deprecated;
CREATE INDEX IF NOT EXISTS idx_behavior_technique ON attack.behavior_examples(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_tactics_reverse ON attack.technique_tactics(tactic_id);
CREATE INDEX IF NOT EXISTS idx_strategy_analytics_reverse ON attack.strategy_analytics(analytic_id);
CREATE INDEX IF NOT EXISTS idx_analytic_components_reverse ON attack.analytic_data_components(data_component_id);
CREATE INDEX IF NOT EXISTS idx_matrix_tactics_reverse ON attack.matrix_tactics(tactic_id);

-- Entity views: browse each type without duplicating node data.
CREATE OR REPLACE VIEW attack.techniques AS
    SELECT *, COALESCE((stix_json->>'x_mitre_is_subtechnique')::boolean, FALSE) AS is_subtechnique
    FROM attack.nodes WHERE type = 'attack-pattern';
CREATE OR REPLACE VIEW attack.tactics AS
    SELECT *, stix_json->>'x_mitre_shortname' AS shortname
    FROM attack.nodes WHERE type = 'x-mitre-tactic';
CREATE OR REPLACE VIEW attack.mitigations AS
    SELECT * FROM attack.nodes WHERE type = 'course-of-action';
CREATE OR REPLACE VIEW attack.detection_strategies AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-detection-strategy';
CREATE OR REPLACE VIEW attack.analytics AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-analytic';
CREATE OR REPLACE VIEW attack.data_sources AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-data-source';
CREATE OR REPLACE VIEW attack.data_components AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-data-component';
CREATE OR REPLACE VIEW attack.matrices AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-matrix';
CREATE OR REPLACE VIEW attack.collections AS
    SELECT * FROM attack.nodes WHERE type = 'x-mitre-collection';
CREATE OR REPLACE VIEW attack.identities AS
    SELECT * FROM attack.nodes WHERE type = 'identity';
CREATE OR REPLACE VIEW attack.marking_definitions AS
    SELECT * FROM attack.nodes WHERE type = 'marking-definition';

-- Log-source names and channels remain available alongside normalized pairs.
CREATE OR REPLACE VIEW attack.analytic_log_sources AS
    SELECT n.id AS analytic_id,
           ref->>'x_mitre_data_component_ref' AS data_component_id,
           ref->>'name' AS log_source,
           ref->>'channel' AS channel
    FROM attack.analytics AS n
    CROSS JOIN LATERAL jsonb_array_elements(
        COALESCE(n.stix_json->'x_mitre_log_source_references', '[]'::jsonb)
    ) AS ref;
