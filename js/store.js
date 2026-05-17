// Central reactive data store. All views read from here; all adapters write here.
// Emits CustomEvents so views can re-render on data changes.

import { EntityType } from './schema.js';

class Store extends EventTarget {
  #state = {
    [EntityType.HOST]: [],
    [EntityType.DOMAIN]: [],
    [EntityType.VULNERABILITY]: [],
    [EntityType.CERTIFICATE]: [],
    [EntityType.THREAT]: [],
    correlations: [],
  };

  load(type, entities) {
    this.#state[type] = Array.isArray(entities) ? [...entities] : [];
    this.#emit('change:' + type);
    this.#emit('change');
  }

  append(type, entities) {
    this.#state[type] = [...(this.#state[type] || []), ...(entities || [])];
    this.#emit('change:' + type);
    this.#emit('change');
  }

  setCorrelations(list) {
    this.#state.correlations = [...(list || [])];
    this.#emit('change:correlations');
    this.#emit('change');
  }

  getAll(type) {
    return [...(this.#state[type] || [])];
  }

  getById(type, id) {
    return (this.#state[type] || []).find(e => e.id === id) ?? null;
  }

  getCorrelations() {
    return [...this.#state.correlations];
  }

  getCorrelationsFor(type, id) {
    return this.#state.correlations.filter(
      c => (c.fromType === type && c.fromId === id) ||
           (c.toType === type && c.toId === id),
    );
  }

  getSummary() {
    const vulns = this.#state[EntityType.VULNERABILITY];
    const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) { if (v.severity in sev) sev[v.severity]++; }

    const certs = this.#state[EntityType.CERTIFICATE];
    const expiredCerts = certs.filter(c => c.isExpired).length;
    const expiringSoon = certs.filter(c => !c.isExpired && c.daysUntilExpiry != null && c.daysUntilExpiry <= 30).length;

    const threats = this.#state[EntityType.THREAT];
    const activeThreats = threats.filter(t => t.severity === 'critical' || t.severity === 'high').length;

    const riskScore = Math.min(100, Math.round(
      (sev.critical * 25 + sev.high * 10 + sev.medium * 3 + sev.low * 1 + activeThreats * 8) /
      Math.max(1, vulns.length + activeThreats) * 8,
    ));

    return {
      hosts: this.#state[EntityType.HOST].length,
      domains: this.#state[EntityType.DOMAIN].length,
      vulnerabilities: vulns.length,
      certificates: certs.length,
      threats: threats.length,
      severityCounts: sev,
      expiredCerts,
      expiringSoon,
      activeThreats,
      riskScore,
    };
  }

  #emit(name) {
    this.dispatchEvent(new CustomEvent(name));
  }
}

export const store = new Store();
