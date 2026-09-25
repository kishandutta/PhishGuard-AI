/**
 * PHISHGUARD AI // SCAN HISTORY & SECURITY AUDIT EXPORTER
 */

const STORAGE_KEY = 'phishguard_scan_history_v2';
const MAX_HISTORY = 30;

export class HistoryManager {
  constructor() {
    this.history = this.load();
  }

  load() {
    try {
      const data = localStorage.getItem(STORAGE_KEY);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  }

  save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.history));
    } catch {
      // Best effort storage
    }
  }

  addScan(scanResult) {
    // Prevent immediate duplicates
    this.history = this.history.filter(item => item.url !== scanResult.url);
    
    // Summary record
    const record = {
      id: 'scan_' + Date.now(),
      url: scanResult.url,
      timestamp: scanResult.timestamp,
      riskScore: scanResult.riskScore,
      safetyLevel: scanResult.safetyLevel,
      status: scanResult.status,
      statusText: scanResult.statusText,
      brandName: scanResult.brand ? scanResult.brand.name : (scanResult.impersonatedBrand ? scanResult.impersonatedBrand.name : (scanResult.trustedTldInfo ? `.${scanResult.domainParts.tld} (${scanResult.trustedTldInfo.category})` : null)),
      findingsCount: scanResult.findings.length
    };

    this.history.unshift(record);
    if (this.history.length > MAX_HISTORY) {
      this.history = this.history.slice(0, MAX_HISTORY);
    }
    this.save();
    return this.history;
  }

  getHistory() {
    return this.history;
  }

  clearHistory() {
    this.history = [];
    localStorage.removeItem(STORAGE_KEY);
  }

  deleteItem(id) {
    this.history = this.history.filter(item => item.id !== id);
    this.save();
    return this.history;
  }

  exportJson(scanResult) {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scanResult, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `PhishGuard_Report_${Date.now()}.json`);
    dlAnchor.click();
  }

  generateTextReport(scanResult) {
    const divider = '========================================================================\n';
    let report = '';
    report += divider;
    report += '          PHISHGUARD AI // THREAT INTELLIGENCE AUDIT REPORT             \n';
    report += divider;
    report += `Timestamp:       ${scanResult.timestamp}\n`;
    report += `Target URL:      ${scanResult.url}\n`;
    report += `Normalized:      ${scanResult.normalizedUrl}\n`;
    report += `Risk Score:      ${scanResult.riskScore}% / 100%\n`;
    report += `Classification:  ${scanResult.statusText}\n`;
    report += `Safety Level:    ${scanResult.safetyLevel}\n`;

    if (scanResult.brand) {
      report += `Verified Brand:  ${scanResult.brand.name} (${scanResult.trustBadge})\n`;
    }
    if (scanResult.trustedTldInfo) {
      report += `Trusted Registry: .${scanResult.domainParts.tld} (${scanResult.trustedTldInfo.badge})\n`;
    }
    if (scanResult.impersonatedBrand) {
      report += `Impersonation:   Targeting ${scanResult.impersonatedBrand.name}\n`;
    }

    report += `Scan Execution:  ${scanResult.scanDurationMs} ms\n`;
    report += divider;
    report += 'DOMAINS & LEXICAL ANATOMY:\n';
    report += ` - Hostname:     ${scanResult.domainParts.hostname}\n`;
    report += ` - Root Domain:  ${scanResult.domainParts.rootDomain}\n`;
    report += ` - Subdomain:    ${scanResult.domainParts.subdomain || '[NONE]'}\n`;
    report += ` - TLD:          .${scanResult.domainParts.tld || 'N/A'}\n`;
    report += ` - Port:         ${scanResult.domainParts.port}\n`;
    report += ` - Path:         ${scanResult.domainParts.pathname}\n`;
    report += divider;
    report += 'SECURITY FINDINGS & RISK BREAKDOWN:\n';

    scanResult.findings.forEach((f, idx) => {
      report += `\n[${idx + 1}] ${f.severity} // ${f.category}: ${f.title}\n`;
      report += `    Impact Score: ${f.impact >= 0 ? '+' : ''}${f.impact}%\n`;
      report += `    Rule Code:    ${f.rule}\n`;
      report += `    Details:      ${f.description}\n`;
    });

    report += divider;
    report += `OVERALL SUMMARY: ${scanResult.threatSummary}\n`;
    report += divider;
    return report;
  }
}

export const historyManager = new HistoryManager();
