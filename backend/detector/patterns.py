"""
ScamShield - Detection Patterns & Dictionaries
Organized keyword, phrase, and regex patterns for scam indicator analysis.
"""

# Shortened URL domains that obscure the true destination
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "buff.ly",
    "shorturl.at",
    "tiny.cc",
    "rebrand.ly",
    "rb.gy",
    "goo.gl",
    "qr.ae",
    "bl.ink",
    "v.gd",
]

# Suspicious / high-risk Top-Level Domains (TLDs) frequently abused in bulk spam
SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".buzz",
    ".club",
    ".click",
    ".loan",
    ".work",
    ".download",
    ".link",
    ".surf",
    ".gq",
    ".cf",
    ".tk",
    ".ml",
    ".ga",
    ".rest",
    ".hair",
    ".quest",
]

# Legitimate security advisory phrases (to avoid false positives on bank warnings)
BENIGN_ADVISORY_PATTERNS = [
    "never share your otp",
    "do not share your otp",
    "never share this code",
    "do not share this code",
    "never share your password",
    "do not share your password",
    "bank will never ask",
    "we will never ask for your",
    "keep this confidential",
    "if not done by you",
    "report to 1930",
    "beware of fraud",
]

# 1. Urgency Indicators
# Pressures victim to act rapidly without thinking or verifying
URGENCY_PATTERNS = [
    "immediately",
    "urgent",
    "urgently",
    "act now",
    "within 24 hours",
    "within 12 hours",
    "within 2 hours",
    "limited time",
    "expires today",
    "expires soon",
    "last chance",
    "hurry",
    "right now",
    "deadline today",
    "action required immediately",
    "immediate action required",
    "time is running out",
    "final notice",
    "strictly confidential",
]

# 2. Threatening Language & Account Suspension
# Uses fear of legal, financial, or service loss to enforce compliance
THREAT_PATTERNS = [
    "account blocked",
    "account has been blocked",
    "account will be blocked",
    "account suspended",
    "account has been suspended",
    "account will be suspended",
    "account deactivated",
    "account will be deactivated",
    "account suspension",
    "avoid suspension",
    "legal action",
    "police case",
    "fir filed",
    "police complaint",
    "arrest warrant",
    "arrest",
    "court order",
    "penalty",
    "electricity disconnected",
    "power cutoff",
    "sim blocked",
    "sim deactivation",
    "service terminated",
    "unauthorized transaction detected",
    "security alert",
]

# 3. OTP & Verification Code Requests (Predatory)
# Asks recipient to send, read, or forward an authentication code
OTP_REQUEST_PATTERNS = [
    "send otp",
    "send your otp",
    "share otp",
    "share the otp",
    "share your otp",
    "tell otp",
    "give otp",
    "enter otp",
    "share code",
    "tell me the code",
    "enter the otp",
    "forward the otp",
    "forward this message",
    "one time password",
    "verification code",
    "send 6 digit code",
    "send 4 digit code",
    "enter code here",
    "provide your otp",
    "reply with otp",
    "confirm your code",
    "share the code",
]

# 4. Password & Credential Requests
# Solicits security credentials, PINs, or logins
PASSWORD_REQUEST_PATTERNS = [
    "password",
    "login credentials",
    "netbanking password",
    "atm pin",
    "security pin",
    "upipin",
    "upi pin",
    "security code",
    "reset credentials",
    "enter your password",
    "send your password",
    "confirm password",
]

# 5. Payment & Fee Demands
# Requests money transfer, deposits, or advance fees
PAYMENT_REQUEST_PATTERNS = [
    "pay now",
    "transfer money",
    "send money",
    "processing fee",
    "registration fee",
    "deposit",
    "payment required",
    "clearance fee",
    "courier charge",
    "delivery charge",
    "upfront fee",
    "refundable fee",
    "pay rs",
    "pay in advance",
    "claim fee",
    "activation fee",
]

# 6. Banking & Financial Details Requests
# Solicits debit/credit card numbers, CVVs, IFSC, or account details
BANKING_PATTERNS = [
    "bank account",
    "debit card",
    "credit card",
    "cvv",
    "card number",
    "16 digit card",
    "expiry date",
    "ifsc code",
    "account number",
    "link your bank",
    "update bank details",
    "claim refund to bank",
]

# 7. Fake Prize & Lottery Scams
# Lures victim with unexpected windfalls, jackpots, or rewards
PRIZE_PATTERNS = [
    "congratulations",
    "winner",
    "won",
    "lottery",
    "jackpot",
    "reward",
    "prize",
    "cash prize",
    "lucky winner",
    "lucky draw",
    "selected for a prize",
    "gift card",
    "claim your prize",
    "claim reward",
    "free gift",
    "bonus credited",
]

# 8. Unrealistic Investment & Crypto Schemes
# Promises guaranteed zero-risk profits or unrealistic returns
INVESTMENT_PATTERNS = [
    "guaranteed returns",
    "double your money",
    "risk-free investment",
    "huge profit",
    "guaranteed profit",
    "100% profit",
    "daily return",
    "crypto scheme",
    "bitcoin doubling",
    "forex trading robot",
    "instant return",
    "get rich quick",
    "invest rs",
]

# 9. Fake Job Offers
# Offers high pay with zero qualifications, often requiring upfront fees
JOB_SCAM_PATTERNS = [
    "work from home",
    "part time job",
    "easy income",
    "daily payout",
    "no experience required",
    "earn from home",
    "typing work",
    "data entry job",
    "youtube like job",
    "telegram task",
    "earn rs",
    "earn 5000 daily",
    "earn 10000 daily",
    "joining fee",
    "interview fee",
]

# 10. KYC & Identity Scams
# Deceives users into updating identity documents on fake portals
KYC_PATTERNS = [
    "kyc expired",
    "update kyc",
    "verify kyc",
    "kyc suspension",
    "kyc verification pending",
    "link pan card",
    "pan card blocked",
    "aadhaar link",
    "kyc document",
    "submit kyc",
]

# 11. Sensitive Personal Information Requests
PERSONAL_INFO_PATTERNS = [
    "aadhaar number",
    "pan number",
    "social security",
    "ssn",
    "mother\'s maiden name",
    "date of birth verification",
]

# 12. Requests to Bypass Normal Procedures
BYPASS_PATTERNS = [
    "do not tell bank",
    "do not inform bank",
    "keep this secret",
    "bypass procedure",
    "offline transfer",
    "contact on telegram only",
    "message on whatsapp only",
]
