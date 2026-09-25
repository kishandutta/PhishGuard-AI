# PHISHGUARD AI // Cyber Threat Intelligence & Phishing Link Detector

An advanced, intelligent **Cybersecurity Phishing Link Detector** with a futuristic cyberpunk HUD interface, dark space theme, neon green/red/cyan accents, synthesized cyber telemetry audio, and a threat intelligence detection engine.

---

## ⚡ Key Capabilities & Features

### 1. 🛡️ Trusted Brand Whitelist & Recognition
- **Pre-Programmed Cryptographic Whitelist Registry**: Extensive database containing verified daily platforms:
  - **Flipkart** (`flipkart.com`, `fkrt.it`, `flipkartcareers.com`, `flipkart.net`)
  - **Amazon** (`amazon.com`, `amazon.in`, `amzn.to`, `amazon.co.uk`, `primevideo.com`, etc.)
  - **Myntra** (`myntra.com`, `myntassets.com`)
  - **Google & Alphabet** (`google.com`, `google.co.in`, `accounts.google.com`, `goo.gl`, `gmail.com`, etc.)
  - **YouTube** (`youtube.com`, `youtu.be`, `googlevideo.com`)
  - **Facebook / Meta** (`facebook.com`, `fb.com`, `fb.me`, `messenger.com`)
  - **Instagram** (`instagram.com`, `instagr.am`, `cdninstagram.com`)
  - **Twitter / X** (`twitter.com`, `x.com`, `t.co`)
  - **WhatsApp** (`whatsapp.com`, `wa.me`, `whatsapp.net`)
  - **Netflix** (`netflix.com`, `nflxso.net`, `nflxext.com`, `nflxvideo.net`)
  - **GitHub** (`github.com`, `github.io`, `github.blog`)
  - **LinkedIn** (`linkedin.com`, `lnkd.in`, `licdn.com`)
  - **Microsoft** (`microsoft.com`, `live.com`, `office.com`, `outlook.com`, `azure.com`, `windows.net`, etc.)
  - Plus **Apple**, **PayPal**, **Spotify**, **Reddit**, **Discord**, **Telegram**.
- **Instant 100% Safe Classification**: Genuine variations and exact matches of official domains bypass false positives and receive a **Verified Enterprise Trust Badge** with category and green HUD certificate.

### 2. 🧠 Advanced Threat Intelligence Engine (Heuristics)
- **Typosquatting & Lookalike Detection**:
  - Damerau-Levenshtein distance calculations against brand registries (e.g., `amzon`, `gogle`).
  - Homoglyph & confusable substitutions (e.g., `0` for `o`, `1` or `l` for `i`, `rn` for `m`).
  - Compound typosquat detection (e.g. `flipkart-login-update.co`, `amzn-security.com`, `g00gle-verify.net`).
- **Subdomain Deception & Spoofing**:
  - Catches malicious domains embedding brand names in subdomains (e.g. `flipkart.com.free-vouchers.net`).
- **Raw IP Address Navigation**:
  - Flags raw IPv4, IPv6, hex-encoded (`0x7f000001`), and octal integer formats.
- **URL Shortener Destination Cloaking**:
  - Detects redirection shorteners (`bit.ly`, `tinyurl.com`, `is.gd`, `cutt.ly`, etc.) that mask final destinations.
- **Deceptive Path Keywords & High-Abuse TLDs**:
  - Detects high-abuse TLDs (`.xyz`, `.top`, `.tk`, `.buzz`, `.ru`, `.cn`, `.fit`, `.cc`, etc.).
  - Correlates risky TLDs with urgency and manipulation lure keywords (`free-gifts`, `claim-reward`, `login-secure`, `otp`, `kyc-update`, `banking`, `wallet`).
- **UserInfo Spoofing (@ Attack)**:
  - Detects credential spoofing in URLs (e.g., `https://google.com@attacker-site.com`).
- **Punycode / IDN Homograph Attacks**:
  - Flags non-Latin Cyrillic/Greek Unicode lookalikes converted to `xn--` Punycode.
- **Shannon Entropy Analysis**:
  - Calculates character randomness to detect Algorithmically Generated Domains (DGA).
- **Executable Payload Detection**:
  - Flags dangerous file extensions (`.exe`, `.scr`, `.bat`, `.apk`, `.vbs`, `.iso`).

### 3. 🖥️ Cyberpunk HUD User Experience
- **Interactive Cyber Canvas**: Dynamic particle mesh and sweeping scan beam.
- **Synthesized Cyber Audio Telemetry**: Real-time browser-synthesized audio effects (click blips, diagnostic radar pings, verified chime, and threat alarms) via Web Audio API. Mute/unmute state saved in localStorage.
- **5-Stage Real-Time Scanning HUD**:
  1. `[01/05] INGESTING TARGET & PARSING PROTOCOL HIERARCHY...`
  2. `[02/05] QUERYING GLOBAL TRUST REGISTRY & BRAND WHITELIST...`
  3. `[03/05] CALCULATING SHANNON ENTROPY & HOMOGLYPH LOOKALIKES...`
  4. `[04/05] CORRELATING TLD ABUSE SCORES & DECEPTIVE LURES...`
  5. `[05/05] SYNTHESIZING HEURISTIC RISK MATRIX... COMPLETE.`
- **Dynamic Radial Risk Gauge**: Animated SVG circle displaying 0% to 100% risk score with neon color shifts.
- **Deconstructed URL Anatomy Inspector**: Color-coded breakdown of Protocol, Subdomain, Root Domain, TLD, Port, Path, and Impersonated Target.
- **Categorized Threat Breakdown Log**: Clear explanation of *why* each vector is dangerous or safe with severity pills (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`) and point impacts.
- **Scan History & Report Exporting**: Persistent localStorage history with 1-click re-testing, clipboard copy, and formatted JSON export.
- **Trusted Brand Explorer Modal**: Searchable in-app directory of all authorized platforms.

---

## 🚀 Quick Start

1. Start the local server:
   ```bash
   npm start
   ```
2. Open your browser at:
   ```
   http://localhost:3000
   ```

---

## 🧪 Built-in Test Scenarios

Try clicking any of the preset simulation chips on the interface:
- **Legitimate Flipkart**: `https://www.flipkart.com/offers-store` -> `100% Safe (Verified Brand Platform)`
- **Official Amazon India**: `https://www.amazon.in/dp/B0CX21P5H2` -> `100% Safe (Verified Brand Platform)`
- **Google Accounts**: `https://accounts.google.com/signin/v2/identifier` -> `100% Safe (Verified Brand Platform)`
- **Official Myntra**: `https://www.myntra.com/men-casual-shirts` -> `100% Safe (Verified Brand Platform)`
- **Flipkart Phishing Clone**: `http://flipkart-login-update.co/claim-reward` -> `100% Risk - Dangerous Phishing Hazard`
- **Amazon Typosquat**: `https://amzn-security.com/verify-account` -> `95% Risk - Dangerous Phishing Hazard`
- **Google Homoglyph**: `https://g00gle-verify.net/accounts/signin` -> `95% Risk - Dangerous Phishing Hazard`
- **Raw IP Attack**: `http://192.168.1.45/banking-login.php` -> `85% Risk - Dangerous Phishing Hazard`
- **Deceptive TLD Lure**: `https://free-gifts.xyz/win-iphone16` -> `55% Risk - Suspicious`
- **Obfuscated Shortener**: `https://bit.ly/secure-login-39281` -> `60% Risk - Suspicious`
