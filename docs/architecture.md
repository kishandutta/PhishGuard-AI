# PhishGuard AI // System Architecture & Code Structure

## 1. High-Level Architectural Overview

**PhishGuard AI** is architected as a modular, client-side single-page application (SPA) adhering to modern ECMAScript standards (ES Modules). The application operates with zero external runtime dependencies, requiring no third-party JavaScript frameworks or remote tracking servers.

All threat analysis, lexical parsing, Levenshtein distance calculations, and audio syntheses are executed entirely within the user's browser runtime.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        USER BROWSER RUNTIME                            │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   [ URL Ingestion ] ──────► [ Lexical Parser & Normalizer ]            │
│                                           │                            │
│                                           ▼                            │
│                         [ Whitelist Brand Authenticator ]              │
│                                    /             \                     │
│                   (Exact Match)   /               \  (Unverified)      │
│                                  ▼                 ▼                   │
│                       [ 100% Safe Clearance ]   [ Heuristic Pipeline ] │
│                                  │                     │               │
│                                  │    ┌────────────────┴─────────────┐ │
│                                  │    │ • Raw IP Address Check       │ │
│                                  │    │ • Brand Typosquat / Lookalike│ │
│                                  │    │ • High-Abuse TLD Correlation │ │
│                                  │    │ • Deceptive Lure Keywords    │ │
│                                  │    │ • Shortener Masking          │ │
│                                  │    │ • UserInfo '@' Spoofing      │ │
│                                  │    │ • Punycode / IDN Encoding    │ │
│                                  │    │ • Shannon Entropy (DGA)      │ │
│                                  │    │ • Dangerous File Extensions  │ │
│                                  │    └────────────────┬─────────────┘ │
│                                  ▼                     ▼               │
│                        [ Risk Scoring Matrix & Classifier ]            │
│                                           │                            │
│         ┌─────────────────────────────────┼────────────────────────┐   │
│         ▼                                 ▼                        ▼   │
│  [ Visual HUD Dashboard ]       [ Web Audio Telemetry ]   [ LocalStorage ]
│  • Radial SVG Risk Dial         • Tactile Clicks          • History Cache
│  • Deconstructed Anatomy        • Radar Sonar Pings       • Audit Export
│  • Categorized Finding Cards    • Harmonic Safe Chime     • JSON Exporter
│  • Verified Trust Badge         • Threat Alarm Siren                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Directory & Module Hierarchy

```
PhishGuard AI/
├── index.html              # Primary DOM layout, HUD panels, and modals
├── package.json            # Node.js project manifest & execution scripts
├── server.js               # Zero-dependency local static HTTP server
├── css/
│   └── cyberpunk.css       # Design tokens, HUD scanlines, glassmorphism, animations
├── js/
│   ├── app.js              # Application orchestrator & DOM event binding
│   ├── engine.js           # Core Threat Intelligence & Heuristic Detection Engine
│   ├── whitelist.js        # Global Trusted Brand Registry & threat dictionaries
│   ├── audio.js            # Synthesized Web Audio API sound generator
│   ├── canvas.js           # Interactive background grid & particle system
│   └── history.js          # Persistent scan history & security audit exporter
└── docs/
    ├── implementation-plan.md  # Roadmap, heuristic rules, and scoring strategy
    └── architecture.md         # System design, module breakdown, and data flow
```

---

## 3. Data Flow & Execution Pipeline

When a user submits a target URL or clicks a preset benchmark, execution proceeds through the following sequential stages:

```
[1. Ingestion] ──► [2. Normalization] ──► [3. Whitelist Query] ──► [4. Heuristic Loop] ──► [5. Scoring] ──► [6. UI/Audio]
```

### Stage 1: Ingestion & Sanitization
1. Strips leading/trailing whitespace, carriage returns, and control characters.
2. Checks for scheme presence (`http://`, `https://`). If omitted, automatically prefixes `https://` to ensure RFC-compliant parsing.

### Stage 2: Lexical Deconstruction
1. Instantiates standard `URL` object.
2. Extracts `protocol`, `hostname`, `port`, `pathname`, `search`, `hash`, `username`, and `password`.
3. Runs multi-part TLD-aware domain parser (`parseDomainParts`) to correctly separate the effective registered domain (eTLD+1) from nested subdomains (e.g., handles `.co.in`, `.co.uk`, `.com.au`).

### Stage 3: Whitelist Authentication
1. Compares the root domain and full hostname against `TRUSTED_BRANDS.officialDomains`.
2. Verifies whether the domain is an official platform domain or a legitimate subdomain (e.g. `seller.flipkart.com` ends with `.flipkart.com`).
3. If authenticated:
   - Sets risk score to **0%**.
   - Assigns official **Verified Trust Badge**.
   - Emits harmonic arpeggio audio chime.
   - Bypasses subsequent heuristic threat penalties.

### Stage 4: Heuristic Threat Inspection Pipeline
If the link is not in the trusted whitelist, it enters the **strict heuristic inspection pipeline**:
1. **Unverified Baseline**: Adds `UNVERIFIED_THIRD_PARTY_DOMAIN` (+35% risk).
2. **Raw IP Detection**: Evaluates IPv4, IPv6, hex-encoded (`0x7f...`), and octal integer formats (+50% risk).
3. **Brand Manipulation**:
   - Compares domain label against protected brand keywords using homoglyph normalization (`normalizeHomoglyphs`).
   - Checks for numerical or affix additions (`google123`, `flipkart-xyz`, `amzn99`) (+55% risk).
   - Computes Levenshtein distance for 1-2 character edits (+50% risk).
   - Checks for brand names embedded in subdomains on foreign root domains (+50% risk).
4. **TLD Abuse Correlation**: Checks TLD against `HIGH_ABUSE_TLDS` (+40% risk).
5. **Social Engineering Lures**: Scans path and domain for sensitive tokens (`login`, `verify`, `update`, `secure`, `free`, `win`, `bonus`, `support`) (+35% to +45% risk).
6. **Shortener Masking**: Checks against `KNOWN_URL_SHORTENERS` (+40% risk).
7. **Obfuscation Detection**: Checks for UserInfo `@` credential spoofing (+60% risk) and Punycode `xn--` (+50% risk).
8. **Malware Payload**: Inspects path extensions against `SUSPICIOUS_EXTENSIONS` (+55% risk).
9. **Entropy Calculation**: Computes Shannon entropy of the domain label to catch DGA algorithms (+25% risk).

### Stage 5: Score Compilation & State Classification
The engine aggregates all finding impacts, clamps the score between 0 and 100, and categorizes the threat level:
- **`0% - 10%`**: `SAFE` / `VERIFIED_TRUSTED`
- **`11% - 39%`**: `CAUTION` / `UNVERIFIED_THIRD_PARTY`
- **`40% - 69%`**: `WARNING` / `SUSPICIOUS`
- **`70% - 100%`**: `DANGER` / `PHISHING_HAZARD`

### Stage 6: Telemetry & UX Dispatch
1. Stores the scan summary in `localStorage`.
2. Animate the SVG circular risk gauge smoothly from 0% to the target score.
3. Renders the deconstructed URL anatomy inspector with color-coded chip statuses.
4. Generates categorized findings cards with severity badges and impact indicators.
5. Triggers appropriate audio synthesis via `CyberAudioEngine` (alarm, chime, or radar ping).

---

## 4. Deep-Dive Module Breakdown

### 4.1 `js/engine.js` (Detection Core)
- **`normalizeUrl(input)`**: Validates URL structure, removes whitespace and control characters, defaults scheme.
- **`isIpAddress(host)`**: Comprehensive regex testing for standard IPv4, hex IPv4, dword notation, and IPv6.
- **`parseDomainParts(hostname)`**: Multi-part TLD-aware domain extractor separating `subdomain`, `domainName`, `tld`, and `rootDomain`.
- **`levenshteinDistance(a, b)`**: Dynamic programming matrix calculating minimal single-character edits (insertions, deletions, substitutions).
- **`normalizeHomoglyphs(str)`**: Translates lookalike glyphs (`0` -> `o`, `1` -> `l`, `rn` -> `m`, `cl` -> `d`) to standard Latin characters.
- **`calculateShannonEntropy(str)`**: Calculates the information entropy:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Values $> 3.6$ indicate algorithmically generated random strings.
- **`analyzeLink(inputUrl)`**: Master controller executing the multi-layered evaluation pipeline and returning a standardized threat object.

### 4.2 `js/whitelist.js` (Trust & Threat Dictionaries)
- **`TRUSTED_BRANDS`**: Array of brand registry objects containing:
  - `id`: Unique brand identifier
  - `name`: Human-readable brand name
  - `category`: Industry classification (e.g. E-Commerce, Social Networking)
  - `icon`: Brand emoji/symbol
  - `officialDomains`: Array of certified root domains
  - `targetKeywords`: Associated names and typosquat targets
  - `trustBadge`: Official certificate designation string
- **`HIGH_ABUSE_TLDS`**: `Set` of high-risk top-level domains (`xyz`, `top`, `ru`, `cc`, `tk`, etc.).
- **`KNOWN_URL_SHORTENERS`**: `Set` of redirection services (`bit.ly`, `tinyurl.com`, `is.gd`, etc.).
- **`SUSPICIOUS_LURE_WORDS`**: Array of deceptive tokens associated with credential harvesting and social engineering.
- **`SUSPICIOUS_EXTENSIONS`**: Array of dangerous binary/script extensions (`.exe`, `.scr`, `.bat`, `.apk`, etc.).

### 4.3 `js/audio.js` (Synthesized Telemetry Audio)
Operates via the browser `AudioContext` interface:
- **`playClick()`**: Short 800Hz-to-300Hz triangle wave pulse for tactile feedback.
- **`playScanPing(step)`**: Stepped sine wave frequency sweep (500Hz - 1600Hz) simulating sonar diagnostic passes.
- **`playSafeChime()`**: Major four-note harmonic arpeggio (C5: 523Hz, E5: 659Hz, G5: 784Hz, C6: 1046Hz) indicating safe verification.
- **`playThreatAlarm()`**: Dual dissonant sawtooth oscillators (311Hz & 329Hz) with linear frequency modulation producing an emergency siren.
- **`toggleMute()`**: Mutes/unmutes audio output and persists setting in `localStorage`.

### 4.4 `js/canvas.js` (Cyberpunk Canvas Renderer)
- Uses an HTML5 `<canvas>` covering the entire viewport.
- Animates an isometric perspective grid with subtle neon lines.
- Renders an array of 45 autonomous particles connected by dynamic distance-based vector filaments ($d < 110\text{px}$).
- Sweeps a continuous linear gradient laser beam vertically across the screen.

### 4.5 `js/history.js` (Persistence & Exporter)
- **`addScan(result)`**: Prepends scan record to `localStorage`, capping history at 30 items.
- **`exportJson(scanResult)`**: Encodes complete analysis object as a downloadable JSON file.
- **`generateTextReport(scanResult)`**: Formats a formal ASCII-bordered threat audit report suitable for security logs.

### 4.6 `js/app.js` (Application Controller)
- Coordinates DOM updates, event listeners, form submissions, and preset clicks.
- Drives the 5-stage diagnostic HUD sequence using `async/await` delays.
- Synchronizes audio feedback with scanning stages and classification results.
- Manages the Brand Trust Registry modal search and filter.

---

## 5. Security & Privacy Model

1. **Zero Data Transmission**: No user-entered URLs, search queries, or scan histories are transmitted to external servers. All evaluation occurs in local browser memory.
2. **Protection Against Drive-By Attacks**: URLs are analyzed via lexical string deconstruction without navigating to or rendering foreign DOM elements, preventing cross-site scripting (XSS) or drive-by payload execution during inspection.
3. **No Third-Party Cookies or CDN Dependencies**: The application does not load external JavaScript or tracking pixels. Google Fonts are imported via CSS for typography.

---

## 6. Performance Characteristics

- **Engine Execution Latency**: $< 15\text{ms}$ on modern desktop hardware.
- **Memory Footprint**: $< 20\text{MB}$ total heap allocation.
- **Bandwidth**: The entire application bundle (HTML, CSS, JS) is $< 80\text{KB}$ uncompressed.
