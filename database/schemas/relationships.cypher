// Threat Intelligence Graph - Relationship Definitions

// Threat Actor relationships
// Threat actors use specific TTPs
CREATE (ta:ThreatActor)-[:USES]->(ttp:TTP);

// Threat actors belong to campaigns
CREATE (ta:ThreatActor)-[:BELONGS_TO]->(c:Campaign);

// Threat actors control IOCs
CREATE (ta:ThreatActor)-[:CONTROLS]->(ioc:IOC);

// Threat actors develop malware
CREATE (ta:ThreatActor)-[:DEVELOPS]->(m:Malware);

// Threat actors target organizations
CREATE (ta:ThreatActor)-[:TARGETS]->(o:Organization);

// Campaign relationships
// Campaigns use specific TTPs
CREATE (c:Campaign)-[:USES]->(ttp:TTP);

// Campaigns target specific assets
CREATE (c:Campaign)-[:TARGETS]->(a:Asset);

// Campaigns involve specific IOCs
CREATE (c:Campaign)-[:INVOLVES]->(ioc:IOC);

// Campaigns target organizations
CREATE (c:Campaign)-[:TARGETS]->(o:Organization);

// IOC relationships
// IOCs are associated with malware
CREATE (ioc:IOC)-[:ASSOCIATED_WITH]->(m:Malware);

// IOCs target specific assets
CREATE (ioc:IOC)-[:TARGETS]->(a:Asset);

// IOCs are used by threat actors
CREATE (ioc:IOC)-[:USED_BY]->(ta:ThreatActor);

// IOCs resolve to other IOCs (e.g., domain to IP)
CREATE (ioc:IOC)-[:RESOLVES_TO]->(ioc2:IOC);

// IOCs are observed on assets
CREATE (ioc:IOC)-[:OBSERVED_ON]->(a:Asset);

// Asset relationships (GNN integration)
// Assets are exposed to IOCs
CREATE (a:Asset)-[:EXPOSED_TO]->(ioc:IOC);

// Assets are vulnerable to TTPs
CREATE (a:Asset)-[:VULNERABLE_TO]->(ttp:TTP);

// Assets belong to organizations
CREATE (a:Asset)-[:BELONGS_TO]->(o:Organization);

// Assets have vulnerabilities
CREATE (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability);

// TTP relationships
// TTPs exploit vulnerabilities
CREATE (ttp:TTP)-[:EXPLOITS]->(v:Vulnerability);

// TTPs are used in campaigns
CREATE (ttp:TTP)-[:USED_IN]->(c:Campaign);

// Malware relationships
// Malware is associated with IOCs
CREATE (m:Malware)-[:ASSOCIATED_WITH]->(ioc:IOC);

// Malware is used by threat actors
CREATE (m:Malware)-[:USED_BY]->(ta:ThreatActor);

// Malware is used in campaigns
CREATE (m:Malware)-[:USED_IN]->(c:Campaign);

// Vulnerability relationships
// Vulnerabilities affect assets
CREATE (v:Vulnerability)-[:AFFECTS]->(a:Asset);

// Vulnerabilities are exploited by TTPs
CREATE (v:Vulnerability)-[:EXPLOITED_BY]->(ttp:TTP);

// Organization relationships
// Organizations own assets
CREATE (o:Organization)-[:OWNS]->(a:Asset);

// Organizations are targeted by threat actors
CREATE (o:Organization)-[:TARGETED_BY]->(ta:ThreatActor);

// Organizations are targeted by campaigns
CREATE (o:Organization)-[:TARGETED_BY]->(c:Campaign);