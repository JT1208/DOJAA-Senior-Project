// Correlation engine: connects entities across datasets using structured matching rules.
// Strategies: host↔domain (DNS A record), host↔vulnerability (service product),
// cert↔domain (SAN), cert↔host (hostname), threat↔host (indicator IP), threat↔vuln (CVE mention).

import { EntityType, createCorrelation } from './schema.js';

export function buildCorrelations(store) {
  const hosts = store.getAll(EntityType.HOST);
  const domains = store.getAll(EntityType.DOMAIN);
  const vulns = store.getAll(EntityType.VULNERABILITY);
  const certs = store.getAll(EntityType.CERTIFICATE);
  const threats = store.getAll(EntityType.THREAT);

  const raw = [
    ...correlateHostDomain(hosts, domains),
    ...correlateHostVuln(hosts, vulns),
    ...correlateCertDomain(certs, domains),
    ...correlateCertHost(certs, hosts),
    ...correlateThreatHost(threats, hosts),
    ...correlateThreatVuln(threats, vulns),
  ];

  // Deduplicate by correlation ID
  const seen = new Set();
  return raw.filter(c => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });
}

function correlateHostDomain(hosts, domains) {
  const result = [];
  for (const domain of domains) {
    const aIps = domain.records.filter(r => r.type === 'A').map(r => r.value);
    for (const host of hosts) {
      if (aIps.includes(host.ip)) {
        result.push(createCorrelation({
          fromType: EntityType.DOMAIN, fromId: domain.id,
          toType: EntityType.HOST, toId: host.id,
          relation: 'resolves-to', confidence: 1.0,
        }));
      }
    }
  }
  return result;
}

function correlateHostVuln(hosts, vulns) {
  const result = [];
  for (const host of hosts) {
    for (const svc of host.services) {
      if (!svc.product) continue;
      // Extract first meaningful keyword from product name for matching
      const keyword = svc.product.toLowerCase().split(/\s+/)[0];
      if (keyword.length < 3) continue;

      for (const vuln of vulns) {
        const affected = vuln.affectedProducts.some(ap => ap.toLowerCase().includes(keyword));
        if (affected) {
          result.push(createCorrelation({
            fromType: EntityType.HOST, fromId: host.id,
            toType: EntityType.VULNERABILITY, toId: vuln.id,
            relation: 'potentially-affected-by', confidence: 0.8,
          }));
        }
      }
    }
  }
  return result;
}

function correlateCertDomain(certs, domains) {
  const result = [];
  for (const cert of certs) {
    for (const domain of domains) {
      const matches = cert.domains.some(san => {
        if (san === domain.name) return true;
        if (san.startsWith('*.')) return domain.name.endsWith('.' + san.slice(2)) || domain.name === san.slice(2);
        return false;
      });
      if (matches) {
        result.push(createCorrelation({
          fromType: EntityType.CERTIFICATE, fromId: cert.id,
          toType: EntityType.DOMAIN, toId: domain.id,
          relation: 'secures-domain', confidence: 1.0,
        }));
      }
    }
  }
  return result;
}

function correlateCertHost(certs, hosts) {
  const result = [];
  for (const cert of certs) {
    for (const host of hosts) {
      if (!host.hostname) continue;
      const matches = cert.domains.some(san => {
        const base = san.startsWith('*.') ? san.slice(2) : san;
        return host.hostname === base || host.hostname.endsWith('.' + base);
      });
      if (matches) {
        result.push(createCorrelation({
          fromType: EntityType.CERTIFICATE, fromId: cert.id,
          toType: EntityType.HOST, toId: host.id,
          relation: 'secures-host', confidence: 0.9,
        }));
      }
    }
  }
  return result;
}

function correlateThreatHost(threats, hosts) {
  const result = [];
  for (const threat of threats) {
    const iocIps = threat.indicators.filter(i => i.type === 'ip').map(i => i.value);
    for (const host of hosts) {
      if (iocIps.includes(host.ip)) {
        result.push(createCorrelation({
          fromType: EntityType.THREAT, fromId: threat.id,
          toType: EntityType.HOST, toId: host.id,
          relation: 'targets', confidence: 0.95,
        }));
      }
    }
    // Also correlate threat to host by hostname match in threat description or tags
    for (const host of hosts) {
      if (host.hostname && threat.description.toLowerCase().includes(host.hostname.toLowerCase())) {
        result.push(createCorrelation({
          fromType: EntityType.THREAT, fromId: threat.id,
          toType: EntityType.HOST, toId: host.id,
          relation: 'references', confidence: 0.7,
        }));
      }
    }
  }
  return result;
}

function correlateThreatVuln(threats, vulns) {
  const result = [];
  for (const threat of threats) {
    for (const vuln of vulns) {
      if (threat.description.includes(vuln.id) ||
          threat.references.some(r => r.includes(vuln.id))) {
        result.push(createCorrelation({
          fromType: EntityType.THREAT, fromId: threat.id,
          toType: EntityType.VULNERABILITY, toId: vuln.id,
          relation: 'exploits', confidence: 0.95,
        }));
      }
    }
  }
  return result;
}
