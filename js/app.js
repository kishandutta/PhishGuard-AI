/**
 * PHISHGUARD AI // MAIN APPLICATION ORCHESTRATOR
 */

import { TRUSTED_BRANDS } from './whitelist.js';
import { analyzeLink } from './engine.js';
import { cyberAudio } from './audio.js';
import { CyberCanvas } from './canvas.js';
import { historyManager } from './history.js';

class PhishGuardApp {
  constructor() {
    this.currentScan = null;
    this.isScanning = false;
    this.init();
  }

  init() {
    // 1. Initialize Cyber Background Canvas
    this.cyberCanvas = new CyberCanvas('cyberCanvas');

    // 2. Cache DOM Elements
    this.urlInput = document.getElementById('urlInput');
    this.btnScan = document.getElementById('btnScan');
    this.scanForm = document.getElementById('scanForm');
    this.btnPasteUrl = document.getElementById('btnPasteUrl');
    this.btnClearUrl = document.getElementById('btnClearUrl');
    this.presetsGrid = document.getElementById('presetsGrid');

    this.scanningHud = document.getElementById('scanningHud');
    this.scanStageTitle = document.getElementById('scanStageTitle');
    this.scanTerminalLog = document.getElementById('scanTerminalLog');
    this.scanProgressBar = document.getElementById('scanProgressBar');

    this.resultsDashboard = document.getElementById('resultsDashboard');
    this.clearanceBanner = document.getElementById('clearanceBanner');
    this.statusShield = document.getElementById('statusShield');
    this.statusClassification = document.getElementById('statusClassification');
    this.statusSubExplanation = document.getElementById('statusSubExplanation');
    this.verifiedTrustBadgeContainer = document.getElementById('verifiedTrustBadgeContainer');

    this.dialScoreNum = document.getElementById('dialScoreNum');
    this.dialCircleFill = document.getElementById('dialCircleFill');

    this.anatomyScanTime = document.getElementById('anatomyScanTime');
    this.anatomyChipsRow = document.getElementById('anatomyChipsRow');

    this.findingsList = document.getElementById('findingsList');
    this.findingsCounter = document.getElementById('findingsCounter');

    this.btnCopyReport = document.getElementById('btnCopyReport');
    this.btnDownloadJson = document.getElementById('btnDownloadJson');

    this.historyTableBody = document.getElementById('historyTableBody');
    this.btnClearHistory = document.getElementById('btnClearHistory');

    this.btnOpenWhitelist = document.getElementById('btnOpenWhitelist');
    this.btnCloseWhitelist = document.getElementById('btnCloseWhitelist');
    this.whitelistModal = document.getElementById('whitelistModal');
    this.whitelistSearchInput = document.getElementById('whitelistSearchInput');
    this.brandsDirectoryGrid = document.getElementById('brandsDirectoryGrid');

    this.btnToggleAudio = document.getElementById('btnToggleAudio');
    this.audioIcon = document.getElementById('audioIcon');
    this.audioText = document.getElementById('audioText');

    // 3. Attach Event Listeners
    this.attachEvents();

    // 4. Initial Renders
    this.renderHistory();
    this.renderWhitelistDirectory();
    this.updateAudioButtonState();
  }

  attachEvents() {
    // Submit handler
    this.scanForm.addEventListener('submit', (e) => {
      e.preventDefault();
      cyberAudio.playClick();
      this.executeScan(this.urlInput.value);
    });

    // Paste button
    this.btnPasteUrl.addEventListener('click', async () => {
      cyberAudio.playClick();
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          this.urlInput.value = text.trim();
          this.showToast('Link pasted from clipboard');
        }
      } catch {
        this.showToast('Clipboard access not allowed or unavailable');
      }
    });

    // Clear button
    this.btnClearUrl.addEventListener('click', () => {
      cyberAudio.playClick();
      this.urlInput.value = '';
      this.urlInput.focus();
    });

    // Preset chip clicks
    this.presetsGrid.addEventListener('click', (e) => {
      const chip = e.target.closest('.preset-chip');
      if (chip && chip.dataset.url) {
        cyberAudio.playClick();
        this.urlInput.value = chip.dataset.url;
        this.executeScan(chip.dataset.url);
      }
    });

    // Copy audit report
    this.btnCopyReport.addEventListener('click', () => {
      if (!this.currentScan) return;
      cyberAudio.playClick();
      const reportText = historyManager.generateTextReport(this.currentScan);
      navigator.clipboard.writeText(reportText).then(() => {
        this.showToast('Security audit report copied to clipboard!');
      });
    });

    // Download JSON report
    this.btnDownloadJson.addEventListener('click', () => {
      if (!this.currentScan) return;
      cyberAudio.playClick();
      historyManager.exportJson(this.currentScan);
      this.showToast('Security report downloaded (JSON)');
    });

    // Clear history
    this.btnClearHistory.addEventListener('click', () => {
      cyberAudio.playClick();
      historyManager.clearHistory();
      this.renderHistory();
      this.showToast('Scan history cleared');
    });

    // Audio toggle
    this.btnToggleAudio.addEventListener('click', () => {
      const muted = cyberAudio.toggleMute();
      this.updateAudioButtonState();
      if (!muted) {
        cyberAudio.playClick();
      }
    });

    // Whitelist modal open/close
    this.btnOpenWhitelist.addEventListener('click', () => {
      cyberAudio.playClick();
      this.whitelistModal.classList.add('active');
    });

    this.btnCloseWhitelist.addEventListener('click', () => {
      cyberAudio.playClick();
      this.whitelistModal.classList.remove('active');
    });

    this.whitelistModal.addEventListener('click', (e) => {
      if (e.target === this.whitelistModal) {
        this.whitelistModal.classList.remove('active');
      }
    });

    this.whitelistSearchInput.addEventListener('input', (e) => {
      this.renderWhitelistDirectory(e.target.value);
    });

    // Escape key closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.whitelistModal.classList.contains('active')) {
        this.whitelistModal.classList.remove('active');
      }
    });
  }

  updateAudioButtonState() {
    if (cyberAudio.isMuted) {
      this.audioIcon.textContent = '🔇';
      this.audioText.textContent = 'AUDIO: OFF';
    } else {
      this.audioIcon.textContent = '🔊';
      this.audioText.textContent = 'AUDIO: ON';
    }
  }

  showToast(message) {
    const existing = document.querySelector('.cyber-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'cyber-toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 3000);
  }

  async executeScan(rawUrl) {
    if (!rawUrl || !rawUrl.trim()) {
      this.showToast('Please enter a target URL to scan');
      this.urlInput.focus();
      return;
    }

    if (this.isScanning) return;
    this.isScanning = true;
    this.btnScan.disabled = true;
    this.btnScan.style.opacity = '0.6';

    // Show HUD loader and hide previous results
    this.resultsDashboard.classList.remove('active');
    this.scanningHud.classList.add('active');
    this.scanningHud.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // Multi-stage diagnostic sequence
    const stages = [
      { pct: 20, title: 'PARSING URL STRUCTURE...', log: '> [01/05] DECONSTRUCTING PROTOCOL, USERINFO & DOMAIN ANATOMY...' },
      { pct: 45, title: 'QUERYING BRAND REGISTRY...', log: '> [02/05] CROSS-REFERENCING TRUSTED ENTERPRISE REPUTATION WHITELIST...' },
      { pct: 70, title: 'ANALYZING HEURISTIC MATRICES...', log: '> [03/05] SCANNING HOMOGLYPHS, TYPOSQUATTING & SHANNON ENTROPY...' },
      { pct: 90, title: 'CORRELATING THREAT FEEDS...', log: '> [04/05] EVALUATING TLD ABUSE FACTOR & DECEPTIVE LURE TOKENS...' },
      { pct: 100, title: 'SYNTHESIZING THREAT REPORT...', log: '> [05/05] HEURISTIC VECTOR COMPILATION COMPLETE.' }
    ];

    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i];
      this.scanStageTitle.textContent = stage.title;
      this.scanTerminalLog.textContent = stage.log;
      this.scanProgressBar.style.width = `${stage.pct}%`;
      cyberAudio.playScanPing(i + 1);
      await new Promise(res => setTimeout(res, 220));
    }

    // Run Engine Analysis
    let result;
    try {
      result = analyzeLink(rawUrl);
    } catch (err) {
      this.scanningHud.classList.remove('active');
      this.isScanning = false;
      this.btnScan.disabled = false;
      this.btnScan.style.opacity = '1';
      this.showToast(err.message || 'Error parsing target URL');
      return;
    }

    this.currentScan = result;

    // Persist to history
    historyManager.addScan(result);
    this.renderHistory();

    // Render results
    setTimeout(() => {
      this.scanningHud.classList.remove('active');
      this.displayResults(result);
      this.isScanning = false;
      this.btnScan.disabled = false;
      this.btnScan.style.opacity = '1';
    }, 200);
  }

  displayResults(result) {
    this.resultsDashboard.classList.add('active');

    // 1. Banner Classes
    this.clearanceBanner.className = 'clearance-banner';
    let bannerStateClass = 'state-safe';
    let shieldEmoji = '🛡️';

    if (result.safetyLevel === 'DANGER') {
      bannerStateClass = 'state-danger';
      shieldEmoji = '☣️';
      cyberAudio.playThreatAlarm();
    } else if (result.safetyLevel === 'WARNING' || result.safetyLevel === 'CAUTION') {
      bannerStateClass = 'state-warning';
      shieldEmoji = '⚠️';
      cyberAudio.playScanPing(5);
    } else {
      bannerStateClass = 'state-safe';
      shieldEmoji = '🛡️';
      cyberAudio.playSafeChime();
    }

    this.clearanceBanner.classList.add(bannerStateClass);
    this.statusShield.textContent = shieldEmoji;
    this.statusClassification.textContent = result.statusText;
    this.statusSubExplanation.textContent = result.threatSummary;

    // 2. Verified Brand or Trusted TLD Trust Badge
    if (result.brand) {
      this.verifiedTrustBadgeContainer.innerHTML = `
        <div class="verified-trust-badge">
          <span class="badge-icon">${result.brand.icon}</span>
          <span>${result.trustBadge} (${result.brand.category})</span>
        </div>
      `;
    } else if (result.trustedTldInfo && result.safetyLevel === 'SAFE') {
      this.verifiedTrustBadgeContainer.innerHTML = `
        <div class="verified-trust-badge" style="background: rgba(0, 243, 255, 0.12); border-color: var(--neon-cyan); color: var(--neon-cyan);">
          <span class="badge-icon">🏛️</span>
          <span>${result.trustedTldInfo.badge} (.${result.domainParts.tld})</span>
        </div>
      `;
    } else if (result.impersonatedBrand) {
      this.verifiedTrustBadgeContainer.innerHTML = `
        <div class="verified-trust-badge" style="background: rgba(255, 0, 85, 0.15); border-color: var(--neon-red); color: #ff85a2;">
          <span class="badge-icon">${result.impersonatedBrand.icon}</span>
          <span>IMPERSONATION ALERT: Mimicking ${result.impersonatedBrand.name}</span>
        </div>
      `;
    } else {
      this.verifiedTrustBadgeContainer.innerHTML = '';
    }

    // 3. Dial Score
    this.animateDialScore(result.riskScore);

    // 4. URL Anatomy Inspector
    this.renderAnatomy(result);

    // 5. Findings Breakdown
    this.renderFindings(result.findings);

    // Scroll smoothly to results
    this.resultsDashboard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  animateDialScore(targetScore) {
    const totalCircumference = 264; // 2 * PI * 42 approx
    const offset = totalCircumference - (targetScore / 100) * totalCircumference;

    this.dialCircleFill.style.strokeDashoffset = offset;

    let current = 0;
    const stepTime = 15;
    const totalSteps = 40;
    const increment = targetScore / totalSteps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= targetScore || targetScore === 0) {
        current = targetScore;
        clearInterval(timer);
      }
      this.dialScoreNum.textContent = `${Math.round(current)}%`;
    }, stepTime);
  }

  renderAnatomy(result) {
    this.anatomyScanTime.textContent = `EXECUTION: ${result.scanDurationMs}ms // ENTROPY: ${result.domainParts.entropy || '0.00'}`;
    const p = result.domainParts;

    const chips = [];

    // Protocol
    chips.push({
      lbl: 'PROTOCOL',
      val: p.protocol.toUpperCase(),
      state: p.protocol === 'https' ? 'chip-safe' : 'chip-danger'
    });

    // Subdomain
    if (p.subdomain) {
      chips.push({
        lbl: 'SUBDOMAIN',
        val: p.subdomain,
        state: result.impersonatedBrand ? 'chip-danger' : 'chip-neutral'
      });
    }

    // Root Domain
    chips.push({
      lbl: 'ROOT DOMAIN',
      val: p.rootDomain,
      state: (result.brand || (result.trustedTldInfo && result.safetyLevel === 'SAFE')) ? 'chip-safe' : (result.impersonatedBrand ? 'chip-danger' : 'chip-neutral')
    });

    // TLD
    if (p.tld) {
      const isHighAbuse = result.findings.some(f => f.rule === 'HIGH_ABUSE_CHEAP_TLD' || f.rule === 'HIGH_ABUSE_TLD_DETECTED');
      const isSafeTld = result.trustedTldInfo && result.safetyLevel === 'SAFE';
      chips.push({
        lbl: 'TLD',
        val: `.${p.tld}`,
        state: isHighAbuse ? 'chip-danger' : (isSafeTld ? 'chip-safe' : 'chip-neutral')
      });
    }

    // Port
    chips.push({
      lbl: 'PORT',
      val: p.port,
      state: (p.port === '80' || p.port === '443') ? 'chip-neutral' : 'chip-danger'
    });

    // Path
    chips.push({
      lbl: 'PATH',
      val: p.pathname.length > 25 ? p.pathname.slice(0, 25) + '...' : p.pathname,
      state: (result.findings.some(f => f.category === 'Malware & Payload Delivery')) ? 'chip-danger' : 'chip-neutral'
    });

    this.anatomyChipsRow.innerHTML = chips.map(c => `
      <div class="anatomy-chip ${c.state}">
        <span class="chip-lbl">${c.lbl}</span>
        <span class="chip-val">${c.val}</span>
      </div>
    `).join('');
  }

  renderFindings(findings) {
    this.findingsCounter.textContent = `${findings.length} VECTOR${findings.length === 1 ? '' : 'S'} ANALYZED`;

    this.findingsList.innerHTML = findings.map(f => {
      let sevClass = 'sev-safe';
      let badgeClass = 'badge-safe';

      if (f.severity === 'CRITICAL') {
        sevClass = 'sev-critical';
        badgeClass = 'badge-critical';
      } else if (f.severity === 'HIGH') {
        sevClass = 'sev-high';
        badgeClass = 'badge-high';
      } else if (f.severity === 'MEDIUM') {
        sevClass = 'sev-medium';
        badgeClass = 'badge-medium';
      } else if (f.severity === 'LOW') {
        sevClass = 'sev-low';
        badgeClass = 'badge-low';
      }

      let impactClass = 'impact-zero';
      let impactText = '0%';
      if (f.impact > 0) {
        impactClass = 'impact-pos';
        impactText = `+${f.impact}% RISK`;
      } else if (f.impact < 0) {
        impactClass = 'impact-neg';
        impactText = `VERIFIED TRUST (+${Math.abs(f.impact)}%)`;
      }

      return `
        <div class="finding-card ${sevClass}">
          <div class="finding-meta">
            <div class="finding-pill-group">
              <span class="sev-badge ${badgeClass}">${f.severity}</span>
              <span class="finding-category">// ${f.category} [${f.rule}]</span>
            </div>
            <div class="finding-impact ${impactClass}">${impactText}</div>
          </div>
          <div class="finding-title-text">${f.title}</div>
          <div class="finding-desc">${f.description}</div>
        </div>
      `;
    }).join('');
  }

  renderHistory() {
    const history = historyManager.getHistory();
    if (history.length === 0) {
      this.historyTableBody.innerHTML = `
        <tr>
          <td colspan="6" class="history-empty-text">
            NO PRIOR SCANS LOGGED IN LOCAL SESSION CACHE
          </td>
        </tr>
      `;
      return;
    }

    this.historyTableBody.innerHTML = history.map(item => {
      const timeStr = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      let statusColor = 'var(--neon-green)';
      if (item.safetyLevel === 'DANGER') statusColor = 'var(--neon-red)';
      if (item.safetyLevel === 'WARNING') statusColor = 'var(--neon-amber)';

      return `
        <tr>
          <td>${timeStr}</td>
          <td class="history-url-cell" title="${item.url}" data-url="${item.url}">${item.url}</td>
          <td>${item.brandName || '[Unknown Host]'}</td>
          <td><strong>${item.riskScore}%</strong></td>
          <td><span style="color: ${statusColor}; font-weight: 700;">${item.status}</span></td>
          <td>
            <button type="button" class="action-btn-subtle btn-retest" data-url="${item.url}" style="padding: 4px 8px; font-size: 0.75rem;">
              RE-TEST
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Re-test clicks
    this.historyTableBody.querySelectorAll('.btn-retest, .history-url-cell').forEach(el => {
      el.addEventListener('click', (e) => {
        const url = e.currentTarget.dataset.url;
        if (url) {
          cyberAudio.playClick();
          this.urlInput.value = url;
          this.executeScan(url);
        }
      });
    });
  }

  renderWhitelistDirectory(query = '') {
    const q = query.toLowerCase().trim();
    const filtered = TRUSTED_BRANDS.filter(b => {
      if (!q) return true;
      return b.name.toLowerCase().includes(q) ||
             b.category.toLowerCase().includes(q) ||
             b.officialDomains.some(d => d.toLowerCase().includes(q));
    });

    if (filtered.length === 0) {
      this.brandsDirectoryGrid.innerHTML = `
        <div style="grid-column: 1/-1; text-align: center; color: var(--text-dim); font-family: var(--font-mono); padding: 20px;">
          NO BRANDS MATCHING "${query.toUpperCase()}"
        </div>
      `;
      return;
    }

    this.brandsDirectoryGrid.innerHTML = filtered.map(b => `
      <div class="brand-card">
        <div class="brand-card-top">
          <span class="brand-card-icon">${b.icon}</span>
          <div>
            <div class="brand-card-name">${b.name}</div>
            <div class="brand-card-cat">${b.category}</div>
          </div>
        </div>
        <p style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 8px;">
          ${b.description}
        </p>
        <div class="brand-domains-list">
          ${b.officialDomains.slice(0, 4).map(d => `<span class="brand-domain-tag">${d}</span>`).join('')}
          ${b.officialDomains.length > 4 ? `<span class="brand-domain-tag">+${b.officialDomains.length - 4} more</span>` : ''}
        </div>
      </div>
    `).join('');
  }
}

// Instantiate application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.phishGuardApp = new PhishGuardApp();
});
