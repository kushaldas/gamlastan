# Golden SAML (SolarWinds / Solorigate) 

Description: A sophisticated attack technique used in the SolarWinds breach. Attackers compromised the ADFS server, stole the private key used to sign SAML assertions, and minted their own "Golden" SAML tokens to bypass authentication entirely and access any federated service (e.g., AWS, Office 365) as any user.

Impact: Critical. Allows persistence and total domain compromise.

Reference: CISA Alert AA20-352A

# XML Signature Wrapping (XSW) Attacks

Description: A class of vulnerabilities where an attacker injects a fake SAML Assertion into the XML document while keeping the original valid signature intact. The application validates the signature of the original assertion but processes the logic of the fake assertion.

Impact: Critical. Authentication bypass and privilege escalation.

Relevant Research: "On Breaking SAML: Be Whoever You Want to Be" (Somorovsky et al.)

# List of CVEs

- CVE-2021-40690	Apache Santuario (xmlsec)	Secure Validation Bypass	The "secure validation" mode could be bypassed via XSLT transforms, potentially allowing retrieval of local files or denial of service.
- CVE-2023-50314	IBM WebSphere (SAML)	Information Disclosure	Vulnerability in SAML Web Single Sign-on (SSO) could allow an attacker to obtain sensitive information.
- CVE-2019-3731	Spring Security SAML	Signature Spoofing	Missing checks in the SAMLResponse processing allowed attackers to spoof signatures.
- CVE-2013-6440	Libxml2 (xmlsec usage)	XXE Injection	XML External Entity (XXE) vulnerability when processing XML signatures, allowing attackers to read local files.

- CVE-2024-45409	Ruby SAML	Signature Verification Bypass	A flaw in XPath selection allowed attackers to bypass signature verification, enabling them to forge SAML responses and log in as any user.
- CVE-2025-29775	xml-crypto	Authentication Bypass	Dubbed "SAMLStorm". A vulnerability in the xml-crypto Node.js library allows attackers to forge signatures by embedding comments in the DigestValue node, bypassing integrity checks.
- CVE-2025-54419	Node-SAML	Signature Validation Bypass	Versions 5.0.1 and below load the assertion from the unsigned original document rather than the verified signed portion, allowing modification of authentication details (e.g., username).
- CVE-2025-66578	xmlseclibs (PHP)	Authentication Bypass	A flaw in libxml2 canonicalization allows xmlseclibs to compute a digest over an empty string when processing invalid XML, treating it as valid. Fixed in 3.1.4. Refs: https://nvd.nist.gov/vuln/detail/CVE-2025-66578 , https://github.com/robrichards/xmlseclibs/security/advisories/GHSA-c4cc-x928-vjw9

- CVE-2017-11427	python-saml (OneLogin)	XSW / Comment Injection	Incorrect handling of nodes with comments during signature verification allowed text modification.
- CVE-2017-11428	ruby-saml (OneLogin)	XSW / Comment Injection	Similar to above; processing of XML nodes allowed attackers to modify content without invalidating the signature.
- CVE-2018-0489	Shibboleth XMLTooling	Improper Validation	Mishandling of XML definitions allowed attackers to alter the interpretation of the XML structure.
- CVE-2017-11429	saml2-js (Clever)	Auth Bypass	Incorrect canonicalization of XML nodes allowed signature bypass.
- CVE-2017-11430	omniauth-saml	Auth Bypass	Vulnerability in the underlying XML processing allowed substitution of values.



