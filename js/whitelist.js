/**
 * PHISHGUARD AI // TRUSTED BRAND WHITELIST & RECOGNITION DATABASE
 * 
 * Pre-programmed verified root domains and recognized variations for major daily platforms:
 * Flipkart, Amazon, Myntra, Google, YouTube, Facebook, Instagram, Twitter/X, WhatsApp,
 * Netflix, GitHub, LinkedIn, Microsoft, plus Apple, PayPal, Spotify, Discord, Reddit, Telegram.
 */

export const TRUSTED_BRANDS = [
  {
    id: 'flipkart',
    name: 'Flipkart',
    category: 'E-Commerce & Retail',
    icon: '🛍️',
    color: '#2874f0',
    accentColor: '#ffe500',
    description: 'India\'s leading e-commerce marketplace platform',
    officialDomains: [
      'flipkart.com',
      'flipkart.net',
      'fkrt.it',
      'flipkartcareers.com',
      '2gud.com',
      'cleartrip.com'
    ],
    // Keywords often targeted in typosquats or brand phishing
    targetKeywords: ['flipkart', 'flipkartpay', 'flipkartplus', 'fkrt', 'supercoins', 'flipkartorder'],
    trustBadge: 'VERIFIED FLIPKART ENTERPRISE ASSET'
  },
  {
    id: 'amazon',
    name: 'Amazon',
    category: 'E-Commerce, Cloud & Entertainment',
    icon: '📦',
    color: '#ff9900',
    accentColor: '#146eb4',
    description: 'Global e-commerce marketplace and AWS cloud infrastructure',
    officialDomains: [
      'amazon.com',
      'amazon.in',
      'amazon.co.uk',
      'amazon.ca',
      'amazon.de',
      'amazon.fr',
      'amazon.it',
      'amazon.es',
      'amazon.co.jp',
      'amazon.com.au',
      'amzn.to',
      'amzn.in',
      'amzn.com',
      'primevideo.com',
      'media-amazon.com',
      'ssl-images-amazon.com',
      'amazon-adsystem.com',
      'amazonpay.in',
      'amazonpay.com',
      'aws.amazon.com'
    ],
    targetKeywords: ['amazon', 'amzn', 'amazonpay', 'primevideo', 'amazonprime', 'awsamazon', 'amznpay'],
    trustBadge: 'VERIFIED AMAZON GLOBAL INFRASTRUCTURE'
  },
  {
    id: 'myntra',
    name: 'Myntra',
    category: 'Fashion & Lifestyle Retail',
    icon: '👗',
    color: '#ff3f6c',
    accentColor: '#f26a10',
    description: 'Leading fashion, lifestyle, and beauty e-commerce destination',
    officialDomains: [
      'myntra.com',
      'myntassets.com',
      'myntra.my'
    ],
    targetKeywords: ['myntra', 'myntrafashion', 'myntrastore', 'myntraoffer', 'myntrasale'],
    trustBadge: 'VERIFIED MYNTRA FASHION NETWORK'
  },
  {
    id: 'google',
    name: 'Google & Alphabet',
    category: 'Search, Cloud & Workspace',
    icon: '🌐',
    color: '#4285f4',
    accentColor: '#ea4335',
    description: 'Search engine, Android, Google Cloud, Workspace, and Identity services',
    officialDomains: [
      'google.com',
      'google.co.in',
      'google.co.uk',
      'google.ca',
      'google.de',
      'google.fr',
      'google.co.jp',
      'goo.gl',
      'gmail.com',
      'google.org',
      'googleapis.com',
      'gstatic.com',
      'googleusercontent.com',
      'googlemail.com',
      '1e100.net',
      'drive.google.com',
      'docs.google.com',
      'accounts.google.com'
    ],
    targetKeywords: ['google', 'gmail', 'g00gle', 'googl', 'googlelogin', 'googleverify', 'googlecloud'],
    trustBadge: 'VERIFIED GOOGLE AUTHENTICATED REALM'
  },
  {
    id: 'youtube',
    name: 'YouTube',
    category: 'Digital Video & Streaming',
    icon: '▶️',
    color: '#ff0000',
    accentColor: '#282828',
    description: 'World\'s largest video sharing platform and digital media network',
    officialDomains: [
      'youtube.com',
      'youtu.be',
      'ytimg.com',
      'googlevideo.com',
      'youtube-nocookie.com'
    ],
    targetKeywords: ['youtube', 'youtu', 'ytuber', 'youtubepremium', 'youtubelogin'],
    trustBadge: 'VERIFIED YOUTUBE MEDIA PIPELINE'
  },
  {
    id: 'facebook',
    name: 'Facebook / Meta',
    category: 'Social Networking',
    icon: '👥',
    color: '#1877f2',
    accentColor: '#00c6ff',
    description: 'Global social network and Meta communication ecosystem',
    officialDomains: [
      'facebook.com',
      'fb.com',
      'fb.me',
      'messenger.com',
      'facebook.net',
      'fbsbx.com',
      'meta.com',
      'fbcdn.net'
    ],
    targetKeywords: ['facebook', 'faceb00k', 'fblogin', 'metasupport', 'facebookverify', 'fbsecurity'],
    trustBadge: 'VERIFIED META ECOSYSTEM CERTIFICATE'
  },
  {
    id: 'instagram',
    name: 'Instagram',
    category: 'Visual Social Media',
    icon: '📷',
    color: '#e1306c',
    accentColor: '#f77737',
    description: 'Photo and video sharing social network powered by Meta',
    officialDomains: [
      'instagram.com',
      'instagr.am',
      'cdninstagram.com',
      'ig.me'
    ],
    targetKeywords: ['instagram', 'instagr', 'iglogin', 'instaverify', 'instabadge', 'instagramhelp'],
    trustBadge: 'VERIFIED INSTAGRAM OFFICIAL REALM'
  },
  {
    id: 'twitter',
    name: 'Twitter / X',
    category: 'Social & Microblogging',
    icon: '𝕏',
    color: '#ffffff',
    accentColor: '#1da1f2',
    description: 'Global real-time public communication and social broadcasting network',
    officialDomains: [
      'twitter.com',
      'x.com',
      't.co',
      'twimg.com',
      'tweetdeck.com'
    ],
    targetKeywords: ['twitter', 'xcorp', 'twitterlogin', 'xverify', 'twitterbadge', 'xpremium'],
    trustBadge: 'VERIFIED X / TWITTER BROADCAST PIPELINE'
  },
  {
    id: 'whatsapp',
    name: 'WhatsApp',
    category: 'Encrypted Instant Messaging',
    icon: '💬',
    color: '#25d366',
    accentColor: '#128c7e',
    description: 'End-to-end encrypted messaging, voice, and business communication',
    officialDomains: [
      'whatsapp.com',
      'wa.me',
      'whatsapp.net'
    ],
    targetKeywords: ['whatsapp', 'whatsap', 'wame', 'walogin', 'whatsappweb', 'whatsappverify'],
    trustBadge: 'VERIFIED WHATSAPP ENCRYPTED GATEWAY'
  },
  {
    id: 'netflix',
    name: 'Netflix',
    category: 'Subscription Streaming',
    icon: '🎬',
    color: '#e50914',
    accentColor: '#221f1f',
    description: 'Global streaming entertainment service for films, series and documentaries',
    officialDomains: [
      'netflix.com',
      'nflxso.net',
      'nflxext.com',
      'nflximg.net',
      'nflxvideo.net',
      'netflixinvestor.com'
    ],
    targetKeywords: ['netflix', 'netflx', 'nflx', 'netflixlogin', 'netflixupdate', 'netflixbilling'],
    trustBadge: 'VERIFIED NETFLIX STREAMING SERVICES'
  },
  {
    id: 'github',
    name: 'GitHub',
    category: 'Software Development & Hosting',
    icon: '🐙',
    color: '#2b3137',
    accentColor: '#2dba4e',
    description: 'World\'s leading software developer platform and Git repository hosting',
    officialDomains: [
      'github.com',
      'github.io',
      'github.blog',
      'githubassets.com',
      'githubusercontent.com',
      'gh.io'
    ],
    targetKeywords: ['github', 'g1thub', 'githublogin', 'githubsecurity', 'githubsupport'],
    trustBadge: 'VERIFIED GITHUB ENTERPRISE DOMAIN'
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    category: 'Professional Social Network',
    icon: '💼',
    color: '#0a66c2',
    accentColor: '#004182',
    description: 'Global professional networking, jobs, and career management platform',
    officialDomains: [
      'linkedin.com',
      'lnkd.in',
      'licdn.com'
    ],
    targetKeywords: ['linkedin', 'linked1n', 'lnkd', 'linkedinlogin', 'linkedinverify'],
    trustBadge: 'VERIFIED LINKEDIN PROFESSIONAL NETWORK'
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    category: 'Operating Systems & Enterprise Cloud',
    icon: '🪟',
    color: '#00a4ef',
    accentColor: '#7fba00',
    description: 'Global enterprise software, Windows, Azure, Office 365, and Outlook services',
    officialDomains: [
      'microsoft.com',
      'live.com',
      'office.com',
      'office365.com',
      'outlook.com',
      'bing.com',
      'msn.com',
      'azure.com',
      'windows.net',
      'sharepoint.com',
      'onedrive.com',
      'microsoftonline.com',
      'msftconnecttest.com'
    ],
    targetKeywords: ['microsoft', 'micros0ft', 'msft', 'office365', 'outlook', 'azurelogin', 'onedrive'],
    trustBadge: 'VERIFIED MICROSOFT TRUSTED IDENTITY DOMAIN'
  },
  {
    id: 'apple',
    name: 'Apple',
    category: 'Consumer Electronics & Services',
    icon: '🍏',
    color: '#a2aaad',
    accentColor: '#0071e3',
    description: 'Hardware, iOS, macOS, iCloud, Apple ID, and App Store ecosystem',
    officialDomains: [
      'apple.com',
      'icloud.com',
      'itunes.com',
      'apple-dns.net',
      'cdn-apple.com'
    ],
    targetKeywords: ['apple', 'icloud', 'appleid', 'applesecurity', 'icloudverify'],
    trustBadge: 'VERIFIED APPLE ECOSYSTEM DOMAIN'
  },
  {
    id: 'paypal',
    name: 'PayPal',
    category: 'Fintech & Digital Payments',
    icon: '💳',
    color: '#003087',
    accentColor: '#0079c1',
    description: 'Global digital payment and merchant transaction processing system',
    officialDomains: [
      'paypal.com',
      'paypal.me',
      'paypalobjects.com'
    ],
    targetKeywords: ['paypal', 'paypa1', 'pay-pal', 'paypalupdate', 'paypalsecure'],
    trustBadge: 'VERIFIED PAYPAL FINANCIAL GATEWAY'
  },
  {
    id: 'spotify',
    name: 'Spotify',
    category: 'Digital Audio & Music Streaming',
    icon: '🎧',
    color: '#1db954',
    accentColor: '#191414',
    description: 'Digital music, podcast, and video streaming service',
    officialDomains: [
      'spotify.com',
      'spoti.fi',
      'scdn.co'
    ],
    targetKeywords: ['spotify', 'spot1fy', 'spotifylogin', 'spotifypremium'],
    trustBadge: 'VERIFIED SPOTIFY AUDIO REALM'
  },
  {
    id: 'reddit',
    name: 'Reddit',
    category: 'Online Communities & Discussion',
    icon: '🤖',
    color: '#ff4500',
    accentColor: '#ffffff',
    description: 'Social news aggregation, web content rating, and discussion website',
    officialDomains: [
      'reddit.com',
      'redd.it',
      'redditmedia.com',
      'redditstatic.com'
    ],
    targetKeywords: ['reddit', 'redd1t', 'redditlogin', 'redditmod'],
    trustBadge: 'VERIFIED REDDIT COMMUNITY REALM'
  },
  {
    id: 'discord',
    name: 'Discord',
    category: 'VoIP & Instant Messaging',
    icon: '👾',
    color: '#5865f2',
    accentColor: '#ffffff',
    description: 'Voice, video and text communication service for gaming and communities',
    officialDomains: [
      'discord.com',
      'discord.gg',
      'discordapp.com',
      'discord.media'
    ],
    targetKeywords: ['discord', 'd1scord', 'discordnitro', 'discordgift', 'discordairdrop'],
    trustBadge: 'VERIFIED DISCORD COMMUNICATION PIPELINE'
  },
  {
    id: 'telegram',
    name: 'Telegram',
    category: 'Cloud-Based Instant Messaging',
    icon: '✈️',
    color: '#229ed9',
    accentColor: '#ffffff',
    description: 'Cloud-based mobile and desktop messaging app with focus on security',
    officialDomains: [
      'telegram.org',
      't.me',
      'telegram.me'
    ],
    targetKeywords: ['telegram', 'telegra', 'telegrarn', 'telegramgift'],
    trustBadge: 'VERIFIED TELEGRAM MESSAGING PIPELINE'
  },
  {
    id: 'wikipedia',
    name: 'Wikipedia & Wikimedia',
    category: 'Public Knowledge & Non-Profit Encyclopedia',
    icon: '📖',
    color: '#006699',
    accentColor: '#3366cc',
    description: 'Global free encyclopedia and open educational infrastructure maintained by the Wikimedia Foundation',
    officialDomains: [
      'wikipedia.org',
      'wikimedia.org',
      'wikidata.org',
      'wiktionary.org',
      'wikibooks.org',
      'wikiquote.org',
      'wikisource.org',
      'wikiversity.org',
      'wikivoyage.org',
      'wikinews.org',
      'wikimediafoundation.org',
      'mediawiki.org'
    ],
    targetKeywords: ['wikipedia', 'wikimedia', 'wikipedi', 'wikki'],
    trustBadge: 'VERIFIED WIKIMEDIA PUBLIC FOUNDATION'
  },
  {
    id: 'archive',
    name: 'Internet Archive',
    category: 'Digital Library & Public Archive',
    icon: '🏛️',
    color: '#333333',
    accentColor: '#4682b4',
    description: 'Non-profit digital library offering free universal access to books, movies, software, and the Wayback Machine',
    officialDomains: [
      'archive.org',
      'openlibrary.org',
      'waybackmachine.org'
    ],
    targetKeywords: ['archive.org', 'waybackmachine'],
    trustBadge: 'VERIFIED INTERNET ARCHIVE FOUNDATION'
  },
  {
    id: 'mozilla',
    name: 'Mozilla Foundation',
    category: 'Open-Source & Internet Standards',
    icon: '🦊',
    color: '#ff7139',
    accentColor: '#000000',
    description: 'Non-profit organization dedicated to keeping the Internet open, accessible, and secure for all',
    officialDomains: [
      'mozilla.org',
      'firefox.com',
      'mozilla.net',
      'getfirefox.com'
    ],
    targetKeywords: ['mozilla', 'firefox'],
    trustBadge: 'VERIFIED MOZILLA OPEN WEB FOUNDATION'
  }
];

/**
 * Categorized Trusted Top-Level Domains (TLDs) and official registry extensions.
 * These extensions represent restricted regulatory authorities, accredited academic institutions,
 * established public foundations, and recognized core internet registries.
 */
export const TRUSTED_TLD_TIERS = {
  // Restricted Government and Military registries (strictly regulated, verified state/national ownership)
  GOVERNMENT: {
    category: 'Official Government & Sovereign Institution',
    badge: 'VERIFIED OFFICIAL GOVERNMENT REGISTRY',
    riskOffset: -40,
    tlds: new Set([
      'gov', 'mil', 'nic.in', 'gov.in', 'gov.uk', 'gov.au', 'gov.ca', 
      'gov.sg', 'gov.za', 'gov.br', 'gov.mx', 'gov.tr', 'gov.my', 
      'gc.ca', 'fed.us', 'state.gov', 'defense.gov', 'mil.in'
    ]),
    patterns: [
      /^gov$/,
      /^mil$/,
      /^gov\.[a-z]{2}$/,
      /^nic\.[a-z]{2}$/,
      /^mil\.[a-z]{2}$/,
      /^govt\.[a-z]{2}$/
    ]
  },

  // Accredited Educational & Academic Institutions
  EDUCATION: {
    category: 'Accredited Educational & Academic Entity',
    badge: 'AUTHENTICATED ACADEMIC / UNIVERSITY REGISTRY',
    riskOffset: -35,
    tlds: new Set([
      'edu', 'ac', 'edu.in', 'ac.in', 'ac.uk', 'edu.au', 'ac.jp', 
      'edu.sg', 'ac.nz', 'ac.za', 'edu.my', 'edu.ca', 'edu.tr', 'ac.kr'
    ]),
    patterns: [
      /^edu$/,
      /^ac$/,
      /^edu\.[a-z]{2}$/,
      /^ac\.[a-z]{2}$/
    ]
  },

  // Legitimate Non-Profit Organizations, Public Foundations & Open Repositories
  ORGANIZATION: {
    category: 'Public Interest & Non-Profit Organization',
    badge: 'RECOGNIZED NON-PROFIT / FOUNDATION TLD',
    riskOffset: -25,
    tlds: new Set([
      'org', 'org.in', 'org.uk', 'org.au', 'org.za', 'org.br', 'org.mx', 'org.my', 'org.nz', 'org.sg', 'or.jp', 'org.tr'
    ]),
    patterns: [
      /^org$/,
      /^org\.[a-z]{2}$/,
      /^or\.[a-z]{2}$/
    ]
  },

  // Established Core Internet Infrastructure & Network Services
  NETWORK: {
    category: 'Core Internet & Network Infrastructure',
    badge: 'ESTABLISHED NETWORK INFRASTRUCTURE TLD',
    riskOffset: -20,
    tlds: new Set([
      'net', 'net.in', 'net.uk', 'net.au', 'net.za', 'net.br', 'net.my', 'net.nz', 'net.sg', 'ne.jp', 'net.tr'
    ]),
    patterns: [
      /^net$/,
      /^net\.[a-z]{2}$/,
      /^ne\.[a-z]{2}$/
    ]
  },

  // Intergovernmental Treaty Organizations
  INTERNATIONAL: {
    category: 'Intergovernmental Treaty Organization',
    badge: 'VERIFIED INTERGOVERNMENTAL ENTITY',
    riskOffset: -40,
    tlds: new Set(['int']),
    patterns: [
      /^int$/
    ]
  }
};

/**
 * Combined set of trusted TLDs for fast lookup
 */
export const TRUSTED_TLDS = new Set([
  'org', 'gov', 'edu', 'net', 'mil', 'int',
  'gov.in', 'gov.uk', 'gov.au', 'gov.ca', 'gov.sg', 'gov.za', 'gc.ca', 'fed.us',
  'edu.in', 'edu.au', 'edu.sg', 'edu.ca', 'edu.my',
  'ac.in', 'ac.uk', 'ac.jp', 'ac.nz', 'ac.za',
  'org.in', 'org.uk', 'org.au', 'org.za', 'org.br', 'or.jp', 'org.sg',
  'net.in', 'net.uk', 'net.au', 'net.za', 'ne.jp', 'net.sg',
  'nic.in', 'mil.in'
]);

/**
 * Checks whether a given TLD string matches any trusted TLD tier
 */
export function getTrustedTldInfo(tld) {
  if (!tld) return null;
  const cleanTld = tld.toLowerCase().trim();

  for (const [key, tier] of Object.entries(TRUSTED_TLD_TIERS)) {
    if (tier.tlds.has(cleanTld)) {
      return { tierKey: key, ...tier };
    }
    for (const pattern of tier.patterns) {
      if (pattern.test(cleanTld)) {
        return { tierKey: key, ...tier };
      }
    }
  }
  return null;
}

/**
 * List of high-abuse top-level domains commonly exploited in mass phishing campaigns
 */
export const HIGH_ABUSE_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'fit', 'work', 
  'click', 'link', 'rest', 'country', 'stream', 'kim', 'loan', 'racing',
  'accountant', 'date', 'faith', 'review', 'party', 'trade', 'webcam',
  'win', 'vip', 'icu', 'monster', 'hair', 'beauty', 'quest', 'cfd',
  'lat', 'sbs', 'agency', 'today', 'cc', 'ru', 'cn', 'su', 'pw'
]);

/**
 * Common legitimate shorteners that obscure the real destination
 */
export const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'ow.ly', 'rb.gy', 
  'buff.ly', 'shorturl.at', 'bl.ink', 'adf.ly', 'bitly.com', 'tiny.cc'
]);

/**
 * High-risk lure words often combined with fake domains
 */
export const SUSPICIOUS_LURE_WORDS = [
  'login', 'signin', 'log-in', 'sign-in', 'verify', 'verification', 'update',
  'secure', 'security', 'account', 'free', 'bonus', 'win', 'winner', 'support',
  'authenticate', 'banking', 'bank', 'wallet', 'claim', 'reward', 'prize',
  'cashback', 'airdrop', 'crypto', 'recover', 'password', 'reset', 'billing',
  'invoice', 'suspend', 'suspended', 'unusual-activity', 'kyc', 'otp',
  'confirm-identity', 'security-alert', 'customer-support', 'service-desk',
  'voucher', 'coupon', 'urgent-action', 'gift'
];

/**
 * Dangerous file extensions commonly seen in drive-by downloads or payload delivery
 */
export const SUSPICIOUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.apk', '.vbs', '.iso', '.cmd', '.msi', 
  '.jar', '.ps1', '.hta', '.wsf', '.pif', '.reg', '.dll'
];
