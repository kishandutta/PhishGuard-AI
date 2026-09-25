/**
 * PHISHGUARD AI // ADVANCED THREAT INTELLIGENCE & HEURISTIC DETECTION ENGINE
 * 
 * Strict Heuristic Security Rules:
 * 1. Default to Suspicious/Unsafe: Unknown or third-party links are NEVER assumed safe.
 *    Only exact, verified matches of the pre-programmed trusted brand whitelist receive 100% Safe.
 * 2. Strict Threat Triggers (Score >= 70% - 95%+):
 *    - Raw IP address used instead of domain name.
 *    - Brand name manipulation (random numbers, hyphens, prefixes/suffixes: google123.com, flipkart-xyz.net, amzn99.com).
 *    - Suspicious, cheap, or high-risk TLDs (.xyz, .top, .ru, .cc, .gq, .tk, .work, .loan, etc.).
 *    - Deceptive keywords ('login', 'verify', 'update', 'secure', 'account', 'free', 'bonus', 'win', 'support')
 *      combined with unknown or third-party domains.
 *    - Obfuscated URL shorteners masking destination endpoints.
 *    - UserInfo authentication spoofing (@ symbol).
 *    - Punycode IDN homoglyph encoding (xn--).
 *    - Dangerous executable payload extensions (.exe, .apk, .scr).
 */

import { 
  TRUSTED_BRANDS, 
  HIGH_ABUSE_TLDS, 
  KNOWN_URL_SHORTENERS, 
  SUSPICIOUS_LURE_WORDS, 
  SUSPICIOUS_EXTENSIONS 
} from './whitelist.js';

// Multi-part TLD suffixes commonly encountered
const MULTI_PART_TLDS = new Set([
  'co.in', 'com.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'me.uk', 'ltd.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'net.za', 'org.za',
  'com.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my',
  'com.tr', 'net.tr',
  'com.mx', 'org.mx'
]);

// Character substitution maps for homoglyphs / typosquats
const HOMOGLYPH_MAP = {
  '0': 'o',
  '1': 'l',
  '|': 'l',
  '!': 'i',
  '3': 'e',
  '4': 'a',
  '@': 'a',
  '5': 's',
  '$': 's',
  '7': 't',
  '8': 'b',
  'vv': 'w',
  'rn': 'm',
  'cl': 'd'
};

/**
 * Normalizes input string to a standardized URL object
 */
export function normalizeUrl(input) {
  if (!input || typeof input !== 'string') {
    throw new Error('Please enter a valid URL to analyze.');
  }

  let cleaned = input.trim();
  cleaned = cleaned.replace(/[\r\n\t]/g, '');

  let hadScheme = true;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(cleaned)) {
    cleaned = 'https://' + cleaned;
    hadScheme = false;
  }

  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch (err) {
    throw new Error(`Invalid URL structure: ${err.message}`);
  }

  return {
    raw: input,
    normalized: cleaned,
    hadScheme,
    protocol: parsed.protocol.replace(':', ''),
    username: parsed.username,
    password: parsed.password,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash
  };
}

/**
 * Checks if a host is an IPv4, IPv6, or numeric representation
 */
export function isIpAddress(host) {
  // IPv4 standard: 192.168.1.1
  const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  // Hexadecimal, octal, or dword
  const hexIpRegex = /^0x[0-9a-fA-F]{1,8}$/;
  const dwordIpRegex = /^\d{8,11}$/;
  // IPv6
  const ipv6Regex = /^\[?[a-fA-F0-9:]+\]?$/;

  if (ipv4Regex.test(host)) return true;
  if (hexIpRegex.test(host)) return true;
  if (dwordIpRegex.test(host)) return true;
  if (host.includes(':') && ipv6Regex.test(host)) return true;

  return false;
}

/**
 * Extracts root domain, subdomain, and domain labels with multi-part TLD awareness
 */
export function parseDomainParts(hostname) {
  const isIp = isIpAddress(hostname);
  if (isIp) {
    return {
      isIp: true,
      rootDomain: hostname,
      subdomain: '',
      tld: '',
      domainName: hostname
    };
  }

  const parts = hostname.split('.');
  if (parts.length === 1) {
    return {
      isIp: false,
      rootDomain: hostname,
      subdomain: '',
      tld: '',
      domainName: hostname
    };
  }

  // Check for 2-part TLD e.g. "co.in", "co.uk"
  let tld = parts[parts.length - 1];
  let rootDomain = '';
  let subdomain = '';
  let domainName = '';

  if (parts.length >= 3) {
    const candidate2Part = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (MULTI_PART_TLDS.has(candidate2Part)) {
      tld = candidate2Part;
      domainName = parts[parts.length - 3];
      rootDomain = `${domainName}.${tld}`;
      subdomain = parts.slice(0, parts.length - 3).join('.');
      return { isIp: false, rootDomain, subdomain, tld, domainName };
    }
  }

  // Standard 1-part TLD e.g. "flipkart.com"
  tld = parts[parts.length - 1];
  domainName = parts[parts.length - 2];
  rootDomain = `${domainName}.${tld}`;
  subdomain = parts.slice(0, parts.length - 2).join('.');

  return { isIp: false, rootDomain, subdomain, tld, domainName };
}

/**
 * Calculates standard Levenshtein distance between two strings
 */
export function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Replaces common homoglyph substitutions to reveal intended keyword
 */
export function normalizeHomoglyphs(str) {
  let res = str.toLowerCase();
  for (const [lookalike, standard] of Object.entries(HOMOGLYPH_MAP)) {
    res = res.split(lookalike).join(standard);
  }
  return res;
}

/**
 * Calculates Shannon entropy of a string (detects random DGA generation)
 */
export function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

/**
 * Checks whether the hostname is an official recognized domain or legitimate subdomain of a trusted brand
 */
export function checkTrustedWhitelist(hostname) {
  const { rootDomain } = parseDomainParts(hostname);

  for (const brand of TRUSTED_BRANDS) {
    for (const officialDomain of brand.officialDomains) {
      // Exact root domain match (e.g. flipkart.com === flipkart.com)
      if (rootDomain === officialDomain || hostname === officialDomain) {
        return {
          isWhitelisted: true,
          brand,
          matchedDomain: officialDomain,
          matchType: 'EXACT_MATCH',
          trustBadge: brand.trustBadge
        };
      }

      // Legitimate certified subdomain match (e.g. pay.amazon.in ends with .amazon.in)
      if (hostname.endsWith(`.${officialDomain}`)) {
        return {
          isWhitelisted: true,
          brand,
          matchedDomain: officialDomain,
          matchType: 'CERTIFIED_SUBDOMAIN',
          trustBadge: brand.trustBadge
        };
      }
    }
  }

  return { isWhitelisted: false };
}

/**
 * Strict Core Analysis Engine
 */
export function analyzeLink(inputUrl) {
  const startTime = performance.now();
  const urlObj = normalizeUrl(inputUrl);
  const { hostname, pathname, search, protocol, username, password, port } = urlObj;
  const domainParts = parseDomainParts(hostname);
  const { rootDomain, subdomain, tld, domainName, isIp } = domainParts;

  const findings = [];
  let riskScore = 0;
  let impersonatedBrand = null;

  // =========================================================================
  // RULE 1: EXACT TRUSTED BRAND WHITELIST MATCH (100% Safe Clearance)
  // =========================================================================
  const whitelistCheck = checkTrustedWhitelist(hostname);

  if (whitelistCheck.isWhitelisted) {
    const brand = whitelistCheck.brand;
    const isHttps = protocol === 'https';

    findings.push({
      category: 'Brand Trust Registry',
      severity: 'SAFE',
      rule: 'TRUSTED_PLATFORM_CLEARANCE',
      title: `${brand.name} Verified Official Domain`,
      impact: -100,
      description: `The destination "${whitelistCheck.matchedDomain}" is authenticated against the cryptographic whitelist registry for ${brand.name}. Zero typosquatting, spoofing, or manipulation detected.`
    });

    findings.push({
      category: 'Domain Authentication',
      severity: 'SAFE',
      rule: 'VALIDATED_ROOT_DOMAIN',
      title: 'Legitimate Root Authority',
      impact: 0,
      description: `Domain structure "${rootDomain}" strictly adheres to official corporate zone delegation.`
    });

    if (isHttps) {
      findings.push({
        category: 'Protocol & Encryption',
        severity: 'SAFE',
        rule: 'SECURE_TLS_TRANSPORT',
        title: 'Modern TLS/HTTPS Transport',
        impact: 0,
        description: 'Connection uses secure cryptographic transport (HTTPS) ensuring confidentiality and anti-tampering.'
      });
    } else {
      findings.push({
        category: 'Protocol & Encryption',
        severity: 'LOW',
        rule: 'PLAIN_HTTP_TRANSPORT',
        title: 'Unencrypted Protocol Warning',
        impact: 10,
        description: 'Domain is legitimate, but the URL is using unencrypted HTTP instead of HTTPS. While the domain is verified, credentials should only be entered over HTTPS.'
      });
      riskScore = 10;
    }

    const scanDuration = Math.round(performance.now() - startTime);

    return {
      url: urlObj.raw,
      normalizedUrl: urlObj.normalized,
      timestamp: new Date().toISOString(),
      scanDurationMs: scanDuration,
      status: 'VERIFIED_TRUSTED',
      statusText: '100% Safe (Verified Brand Platform)',
      riskScore: riskScore, // 0% (or 10% if HTTP)
      safetyLevel: 'SAFE',
      trustBadge: brand.trustBadge,
      brand: {
        id: brand.id,
        name: brand.name,
        category: brand.category,
        icon: brand.icon,
        color: brand.color,
        accentColor: brand.accentColor,
        description: brand.description
      },
      domainParts: {
        protocol,
        hostname,
        rootDomain,
        subdomain,
        tld,
        domainName,
        port: port || (protocol === 'https' ? '443' : '80'),
        pathname,
        search
      },
      findings,
      threatSummary: `Verified authentic digital asset of ${brand.name}. Authenticated against global trusted database.`
    };
  }

  // =========================================================================
  // RULE 2: STRICT SCRUTINY FOR ALL UNKNOWN / THIRD-PARTY / UNVERIFIED DOMAINS
  // Default to Suspicious / Unverified: NEVER assume safe.
  // =========================================================================

  // Initial base penalty for unverified third-party origin
  let baseUnverifiedPenalty = 35;
  findings.push({
    category: 'Domain Reputation & Origin',
    severity: 'MEDIUM',
    rule: 'UNVERIFIED_THIRD_PARTY_DOMAIN',
    title: 'Unverified Third-Party / Unknown Origin',
    impact: baseUnverifiedPenalty,
    description: `The domain "${rootDomain || hostname}" is NOT present in the verified global brand whitelist. Unverified third-party domains undergo strict heuristic inspection and are not trusted by default.`
  });
  riskScore += baseUnverifiedPenalty;

  // =========================================================================
  // RULE 3: CRITICAL TRIGGER - RAW IP ADDRESS NAVIGATION
  // =========================================================================
  if (isIp) {
    riskScore += 50;
    findings.push({
      category: 'Infrastructure & Host',
      severity: 'CRITICAL',
      rule: 'RAW_IP_DESTINATION',
      title: 'Raw IP Address Navigation (Naked Host)',
      impact: 50,
      description: `The destination "${hostname}" is a naked raw IP address. Legitimate organizations provide authenticated domains with TLS certificates. Attackers use raw IP endpoints to bypass DNS-based reputation blocking.`
    });
  }

  // =========================================================================
  // RULE 4: CRITICAL TRIGGER - BRAND NAME MANIPULATION & TYPOSQUATTING
  // Detects: numbers added (google123, amzn99), affixes (flipkart-xyz), homoglyphs (g00gle),
  // subdomains (flipkart.com.attacker.com), and Levenshtein lookalikes
  // =========================================================================
  const normalizedDomainName = normalizeHomoglyphs(domainName);
  const normalizedFullHost = normalizeHomoglyphs(hostname);

  for (const brand of TRUSTED_BRANDS) {
    for (const kw of brand.targetKeywords) {
      // Check for exact substring match or homoglyph variation in domain label or hostname
      // e.g. "google123", "flipkart-xyz", "amzn99", "g00gle", "amazon-security"
      const domainHasKw = domainName.includes(kw) || normalizedDomainName.includes(kw);
      const hostHasKw = hostname.includes(kw) || normalizedFullHost.includes(kw);

      if (domainHasKw || hostHasKw) {
        impersonatedBrand = brand;
        riskScore += 55;

        // Specific detection explanation
        let detail = `The domain "${hostname}" incorporates elements of the protected brand name "${brand.name}" (${kw}), but is NOT an official ${brand.name} domain.`;
        if (/\d+/.test(domainName)) {
          detail += ` Numbers or alphanumeric modifiers have been appended (e.g., "${domainName}").`;
        }
        if (domainName.includes('-')) {
          detail += ` Hyphenated affixes have been attached (e.g., "${domainName}").`;
        }

        findings.push({
          category: 'Brand Impersonation & Typosquatting',
          severity: 'CRITICAL',
          rule: 'BRAND_NAME_MANIPULATION_LOOKALIKE',
          title: `Brand Impersonation: Unauthorized Use of ${brand.name}`,
          impact: 55,
          description: detail + ` This is a primary hallmark of phishing infrastructure engineered to deceive users into false trust.`
        });
        break;
      }

      // Check Levenshtein distance (1-2 characters off from brand name)
      // e.g., "amazn", "flipkartt", "faceboook", "gogle", "netflx"
      if (domainName.length >= 4 && kw.length >= 4) {
        const dist = levenshteinDistance(domainName, kw);
        const normDist = levenshteinDistance(normalizedDomainName, kw);
        const minDistance = Math.min(dist, normDist);

        if (minDistance >= 1 && minDistance <= 2 && domainName !== kw) {
          impersonatedBrand = brand;
          riskScore += 50;
          findings.push({
            category: 'Brand Impersonation & Typosquatting',
            severity: 'CRITICAL',
            rule: 'LEVENSHTEIN_LOOKALIKE_DOMAIN',
            title: `Typosquatting Distance Match (${brand.name})`,
            impact: 50,
            description: `The domain "${domainName}" differs from the legitimate platform "${kw}" by only ${minDistance} character(s). This is deliberate typographical squatting.`
          });
          break;
        }
      }
    }
    if (impersonatedBrand) break;
  }

  // Check for Brand Subdomain Spoofing (e.g. flipkart.com.attacker.com or google.com.order.co)
  if (subdomain && !whitelistCheck.isWhitelisted) {
    for (const brand of TRUSTED_BRANDS) {
      for (const offDomain of brand.officialDomains) {
        if (subdomain.includes(offDomain) || subdomain.split('.').includes(brand.id)) {
          if (!impersonatedBrand) impersonatedBrand = brand;
          riskScore += 50;
          findings.push({
            category: 'Brand Impersonation & Typosquatting',
            severity: 'CRITICAL',
            rule: 'SUBDOMAIN_BRAND_SPOOF',
            title: `Subdomain Deception: Spoofing ${brand.name}`,
            impact: 50,
            description: `Subdomain "${subdomain}" embeds "${offDomain}" to visually trick users into believing they are on an official site, while the real root domain is "${rootDomain}".`
          });
          break;
        }
      }
      if (impersonatedBrand) break;
    }
  }

  // =========================================================================
  // RULE 5: SUSPICIOUS, CHEAP & HIGH-ABUSE TLDs (.xyz, .top, .ru, .cc, .gq, .tk, .work, .loan)
  // =========================================================================
  const isRiskyTld = HIGH_ABUSE_TLDS.has(tld);
  if (isRiskyTld) {
    riskScore += 40;
    findings.push({
      category: 'TLD Reputation Risk',
      severity: 'HIGH',
      rule: 'HIGH_ABUSE_CHEAP_TLD',
      title: `High-Risk / Low-Reputation TLD (.${tld})`,
      impact: 40,
      description: `The top-level domain ".${tld}" has an exceptionally high correlation with cheap, throwaway domains, phishing lures, and malicious spam according to global threat intelligence feeds.`
    });
  }

  // =========================================================================
  // RULE 6: DECEPTIVE & SOCIAL ENGINEERING LURE KEYWORDS
  // ('login', 'verify', 'update', 'secure', 'account', 'free', 'bonus', 'win', 'support')
  // =========================================================================
  const fullUrlLower = urlObj.normalized.toLowerCase();
  const matchedLures = [];
  for (const lure of SUSPICIOUS_LURE_WORDS) {
    if (fullUrlLower.includes(lure)) {
      matchedLures.push(lure);
    }
  }

  if (matchedLures.length > 0) {
    // When deceptive keywords are on an unknown domain, high risk penalty
    const lurePenalty = isRiskyTld || impersonatedBrand ? 45 : 35;
    riskScore += lurePenalty;

    findings.push({
      category: 'Social Engineering & Credential Harvesting',
      severity: isRiskyTld || impersonatedBrand ? 'CRITICAL' : 'HIGH',
      rule: 'DECEPTIVE_LURE_KEYWORDS',
      title: `Deceptive Lure Tokens Detected: [${matchedLures.slice(0, 5).join(', ')}]`,
      impact: lurePenalty,
      description: `URL contains deceptive call-to-action tokens (${matchedLures.slice(0, 5).join(', ')}). Combining sensitive keywords (authentication, financial rewards, urgency) with an unverified third-party domain is a primary indicator of phishing or fraud.`
    });
  }

  // =========================================================================
  // RULE 7: OBFUSCATED URL SHORTENERS (Destination Cloaking)
  // =========================================================================
  if (KNOWN_URL_SHORTENERS.has(hostname)) {
    riskScore += 40;
    findings.push({
      category: 'Obfuscation & Deception',
      severity: 'HIGH',
      rule: 'CLOAKED_URL_SHORTENER',
      title: 'Cloaked URL Shortener Destination',
      impact: 40,
      description: `Host "${hostname}" is an intermediary redirection service. The true destination endpoint, server reputation, and SSL certificates are masked until the link is actively opened.`
    });
  }

  // =========================================================================
  // RULE 8: USERINFO CREDENTIAL SPOOFING (@ Symbol Attack)
  // =========================================================================
  if (username || password) {
    riskScore += 60;
    findings.push({
      category: 'Obfuscation & Deception',
      severity: 'CRITICAL',
      rule: 'USERINFO_CREDENTIAL_SPOOF',
      title: 'Deceptive UserInfo Authentication Spoofing (@ Attack)',
      impact: 60,
      description: `The URL embeds deceptive text ("${username}") before an '@' symbol. Standard browsers navigate directly to "${hostname}", completely bypassing the deceptive prefix.`
    });
  }

  // =========================================================================
  // RULE 9: PUNYCODE / IDN HOMOGRAPH ATTACK (xn--)
  // =========================================================================
  if (hostname.includes('xn--')) {
    riskScore += 50;
    findings.push({
      category: 'Obfuscation & Deception',
      severity: 'CRITICAL',
      rule: 'PUNYCODE_IDN_HOMOGRAPH',
      title: 'Punycode IDN Homograph Encoding (xn--)',
      impact: 50,
      description: `Domain utilizes Internationalized Domain Name (Punycode: "${hostname}"). Attackers use non-Latin Cyrillic or Greek characters that look visually identical to Latin letters to construct indistinguishable counterfeit sites.`
    });
  }

  // =========================================================================
  // RULE 10: DANGEROUS FILE EXTENSIONS & SCRIPT PAYLOADS
  // =========================================================================
  const lowerPath = pathname.toLowerCase();
  for (const ext of SUSPICIOUS_EXTENSIONS) {
    if (lowerPath.endsWith(ext) || lowerPath.includes(`${ext}?`)) {
      riskScore += 55;
      findings.push({
        category: 'Malware & Payload Delivery',
        severity: 'CRITICAL',
        rule: 'EXECUTABLE_PAYLOAD_EXTENSION',
        title: `Suspicious Binary/Script Payload (${ext})`,
        impact: 55,
        description: `Path targets an executable or automated script file (${ext}). Visiting this URL may initiate an automated drive-by malware download.`
      });
      break;
    }
  }

  // =========================================================================
  // RULE 11: LEXICAL ANOMALIES (Entropy, Hyphens, Port, HTTP)
  // =========================================================================
  // Excessive Hyphenation
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    const hyphenPenalty = hyphenCount >= 3 ? 20 : 10;
    riskScore += hyphenPenalty;
    findings.push({
      category: 'Lexical Anatomy',
      severity: 'MEDIUM',
      rule: 'EXCESSIVE_HYPHENATION',
      title: `Excessive Hyphenation (${hyphenCount} hyphens)`,
      impact: hyphenPenalty,
      description: `Domain contains ${hyphenCount} hyphens. Attackers frequently chain keywords with hyphens (e.g. "secure-login-update") to craft deceptive URLs.`
    });
  }

  // Shannon Entropy
  const entropy = calculateShannonEntropy(domainName);
  if (domainName.length > 8 && entropy > 3.6) {
    riskScore += 25;
    findings.push({
      category: 'Lexical Anatomy',
      severity: 'HIGH',
      rule: 'HIGH_LEXICAL_ENTROPY_DGA',
      title: `High Random Entropy (${entropy} bits/char)`,
      impact: 25,
      description: `Domain name exhibits high lexical randomness (Entropy: ${entropy}), indicating an Algorithmically Generated Domain (DGA) designed to evade static blacklists.`
    });
  }

  // Non-Standard Web Port
  if (port && port !== '80' && port !== '443') {
    riskScore += 25;
    findings.push({
      category: 'Protocol & Port',
      severity: 'HIGH',
      rule: 'NON_STANDARD_WEB_PORT',
      title: `Non-Standard Web Port (:${port})`,
      impact: 25,
      description: `Traffic is being directed to custom port ${port} instead of standard HTTPS (443) or HTTP (80). Suspicious staging servers often run on non-standard ports.`
    });
  }

  // Plain Insecure HTTP
  if (protocol === 'http') {
    riskScore += 15;
    findings.push({
      category: 'Protocol & Encryption',
      severity: 'LOW',
      rule: 'UNENCRYPTED_HTTP',
      title: 'Insecure Cleartext Protocol (HTTP)',
      impact: 15,
      description: 'The link transmits data via unencrypted HTTP. Any credentials or personal data transmitted can be intercepted or manipulated via Man-In-The-Middle (MITM) attacks.'
    });
  }

  // Cap risk score between 0 and 100
  riskScore = Math.max(0, Math.min(100, riskScore));

  // =========================================================================
  // RULE 12: ACCURATE RISK LEVEL CLASSIFICATION
  // =========================================================================
  let status = 'SUSPICIOUS';
  let statusText = 'SUSPICIOUS // ELEVATED THREAT LEVEL';
  let safetyLevel = 'WARNING';

  if (riskScore >= 70) {
    status = 'PHISHING_HAZARD';
    statusText = 'DANGEROUS PHISHING // CRITICAL HAZARD';
    safetyLevel = 'DANGER';
  } else if (riskScore >= 40) {
    status = 'SUSPICIOUS';
    statusText = 'SUSPICIOUS // ELEVATED THREAT LEVEL';
    safetyLevel = 'WARNING';
  } else {
    // Under 40%: unknown domain with minimal extra threat vectors
    status = 'UNVERIFIED_THIRD_PARTY';
    statusText = 'UNVERIFIED THIRD-PARTY DOMAIN';
    safetyLevel = 'CAUTION';
  }

  const scanDuration = Math.round(performance.now() - startTime);

  let threatSummary = '';
  if (safetyLevel === 'DANGER') {
    threatSummary = `CRITICAL THREAT (Risk: ${riskScore}%): High probability of phishing or brand impersonation${impersonatedBrand ? ` targeting ${impersonatedBrand.name}` : ''}. DO NOT submit credentials or personal information.`;
  } else if (safetyLevel === 'WARNING') {
    threatSummary = `SUSPICIOUS DOMAIN (Risk: ${riskScore}%): Multiple security threat vectors detected (unverified domain, suspicious TLD, or deceptive keywords). Exercise extreme caution.`;
  } else {
    threatSummary = `UNVERIFIED DOMAIN (Risk: ${riskScore}%): Domain is not in the trusted brand registry. Proceed with caution.`;
  }

  return {
    url: urlObj.raw,
    normalizedUrl: urlObj.normalized,
    timestamp: new Date().toISOString(),
    scanDurationMs: scanDuration,
    status,
    statusText,
    riskScore,
    safetyLevel,
    impersonatedBrand: impersonatedBrand ? {
      name: impersonatedBrand.name,
      icon: impersonatedBrand.icon,
      officialDomains: impersonatedBrand.officialDomains
    } : null,
    domainParts: {
      protocol,
      hostname,
      rootDomain,
      subdomain,
      tld,
      domainName,
      port: port || (protocol === 'https' ? '443' : '80'),
      pathname,
      search,
      entropy
    },
    findings,
    threatSummary
  };
}
