// Threat Intelligence Graph - Node Constraints and Indexes

// IOC Node Constraints
CREATE CONSTRAINT ioc_id IF NOT EXISTS FOR (i:IOC) REQUIRE i.id IS UNIQUE;
CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE;

// Threat Actor Node Constraints
CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.id IS UNIQUE;
CREATE CONSTRAINT threat_actor_name IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.name IS UNIQUE;

// Campaign Node Constraints
CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT campaign_name IF NOT EXISTS FOR (c:Campaign) REQUIRE c.name IS UNIQUE;

// Asset Node Constraints (for GNN integration)
CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE;

// Malware Node Constraints
CREATE CONSTRAINT malware_id IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE;
CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE;

// TTP Node Constraints
CREATE CONSTRAINT ttp_id IF NOT EXISTS FOR (t:TTP) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT ttp_mitre_id IF NOT EXISTS FOR (t:TTP) REQUIRE t.mitre_id IS UNIQUE;

// Vulnerability Node Constraints
CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;

// Organization Node Constraints
CREATE CONSTRAINT organization_id IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;

// Indexes for performance
CREATE INDEX ioc_type_index IF NOT EXISTS FOR (i:IOC) ON (i.type);
CREATE INDEX ioc_confidence_index IF NOT EXISTS FOR (i:IOC) ON (i.confidence);
CREATE INDEX ioc_first_seen_index IF NOT EXISTS FOR (i:IOC) ON (i.first_seen);
CREATE INDEX ioc_last_seen_index IF NOT EXISTS FOR (i:IOC) ON (i.last_seen);

CREATE INDEX threat_actor_country_index IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.country);
CREATE INDEX threat_actor_motivation_index IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.motivation);
CREATE INDEX threat_actor_status_index IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.status);

CREATE INDEX campaign_status_index IF NOT EXISTS FOR (c:Campaign) ON (c.status);
CREATE INDEX campaign_start_date_index IF NOT EXISTS FOR (c:Campaign) ON (c.start_date);
CREATE INDEX campaign_end_date_index IF NOT EXISTS FOR (c:Campaign) ON (c.end_date);

CREATE INDEX asset_type_index IF NOT EXISTS FOR (a:Asset) ON (a.type);
CREATE INDEX asset_environment_index IF NOT EXISTS FOR (a:Asset) ON (a.environment);

CREATE INDEX malware_family_index IF NOT EXISTS FOR (m:Malware) ON (m.family);
CREATE INDEX malware_type_index IF NOT EXISTS FOR (m:Malware) ON (m.type);

CREATE INDEX ttp_tactic_index IF NOT EXISTS FOR (t:TTP) ON (t.tactic);
CREATE INDEX ttp_technique_index IF NOT EXISTS FOR (t:TTP) ON (t.technique);

CREATE INDEX vulnerability_severity_index IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);
CREATE INDEX vulnerability_cvss_index IF NOT EXISTS FOR (v:Vulnerability) ON (v.cvss_score);