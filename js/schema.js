// Unified entity types, factory functions, and normalization utilities.
// All external data must pass through these factories before entering the store.

export const EntityType = Object.freeze({
  HOST: 'host',
  DOMAIN: 'domain',
  VULNERABILITY: 'vulnerability',
  CERTIFICATE: 'certificate',
  THREAT: 'threat',
});

export const SeverityLevel = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#60a5fa',
};

export function normalizeSeverity(input) {
  if (input == null) return SeverityLevel.LOW;
  const s = String(input).toLowerCase().trim();
  if (s.startsWith('crit')) return SeverityLevel.CRITICAL;
  if (s.startsWith('hi')) return SeverityLevel.HIGH;
  if (s.startsWith('med')) return SeverityLevel.MEDIUM;
  if (s === 'info' || s === 'informational' || s === 'none') return SeverityLevel.INFO;
  if (s.startsWith('lo') || s === '0') return SeverityLevel.LOW;
  const n = parseFloat(input);
  if (!isNaN(n)) {
    if (n >= 9.0) return SeverityLevel.CRITICAL;
    if (n >= 7.0) return SeverityLevel.HIGH;
    if (n >= 4.0) return SeverityLevel.MEDIUM;
    return SeverityLevel.LOW;
  }
  return SeverityLevel.LOW;
}

export function createHost({
  id, ip, hostname = null, ports = [], services = [], os = null,
  country = null, asn = null, org = null, lastSeen = null, source = 'unknown', tags = [],
}) {
  return { id, type: EntityType.HOST, ip, hostname, ports, services, os, country, asn, org, lastSeen, source, tags };
}

export function createDomain({
  id, name, records = [], registrar = null, created = null,
  expires = null, subdomains = [], ips = [], source = 'unknown', tags = [],
}) {
  return { id, type: EntityType.DOMAIN, name, records, registrar, created, expires, subdomains, ips, source, tags };
}

export function createVulnerability({
  id, title, description = '', severity, cvss = null, cvssVector = null,
  affectedProducts = [], published = null, modified = null,
  references = [], cwe = null, source = 'unknown', tags = [],
}) {
  return {
    id, type: EntityType.VULNERABILITY, title, description,
    severity: normalizeSeverity(severity), cvss, cvssVector,
    affectedProducts, published, modified, references, cwe, source, tags,
  };
}

export function createCertificate({
  id, subject, issuer, domains = [], validFrom = null, validTo = null,
  algorithm = null, fingerprint = null, serialNumber = null, source = 'unknown', tags = [],
}) {
  const now = Date.now();
  const expiry = validTo ? new Date(validTo).getTime() : null;
  const isExpired = expiry != null && expiry < now;
  const daysUntilExpiry = expiry != null ? Math.floor((expiry - now) / 86400000) : null;
  return {
    id, type: EntityType.CERTIFICATE, subject, issuer, domains, validFrom, validTo,
    isExpired, daysUntilExpiry, algorithm, fingerprint, serialNumber, source, tags,
  };
}

export function createThreat({
  id, category, title, description = '', severity, indicators = [],
  references = [], firstSeen = null, lastSeen = null, source = 'unknown', tags = [],
}) {
  return {
    id, type: EntityType.THREAT, category, title, description,
    severity: normalizeSeverity(severity), indicators, references, firstSeen, lastSeen, source, tags,
  };
}

export function createCorrelation({ fromType, fromId, toType, toId, relation, confidence = 1.0 }) {
  return {
    id: `${fromType}:${fromId}→${toType}:${toId}:${relation}`,
    fromType, fromId, toType, toId, relation, confidence,
  };
}
