"""What each testssl.sh test cvENGINE records means, in a practitioner's words, and how to read what the test said.

``tls_audit`` records the tests named in its ``VULNS`` and ``CONFIG`` tables, plus the listener that completes no handshake
(``tlsa_no_handshake``). Every one has an entry in ``CATALOGUE``: a clear name with the CVE where one exists, what the issue is and
what an attacker needs, the exact read-only commands to confirm it by hand (filled with the finding's host and port), the fix, and the
highest severity a proven result of that test deserves (``ceiling``). ``describe_result`` turns testssl.sh's result string
("likely VULNERABLE with 00") into one plain sentence, and ``assess`` decides how sure the result is: *proven*, *possible* (a heuristic
or a potential: never proof) or *exposure* (the precondition is present, whether it is exploitable depends on clients or the
application).

Nothing here runs anything. The commands are shown for a person to run: the server never scans (the audit runs on a Sentinel), and
every value placed in a command is validated first (``confirm_guide._host`` and ``_port``). Pure: no database, no network.

Result formats come from testssl.sh 3.2's own source (the ``fileout`` lines of each ``run_*`` function). The report items cvENGINE reads
carry ``id``, ``severity``, ``finding`` and ``cve``."""
import re
from dataclasses import dataclass

from cveFeed import confirm_guide

CRITICAL, HIGH, MEDIUM, LOW = 4, 3, 2, 1
UNPROVEN_CEILING = MEDIUM  # a result that is not proven is never rated above Medium, whatever testssl.sh says of it
STARTTLS_PORTS = {25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp', 389: 'ldap'}  # as tls_audit.STARTTLS_PORTS
NO_HANDSHAKE = 'no_handshake'  # catalogue id of the listener that completes no handshake (check tlsa_no_handshake)
SEVERITY_WORDS = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}

PROVEN, POSSIBLE, EXPOSURE = 'proven', 'possible', 'exposure'
CONFIRMED, UNCONFIRMED = 'confirmed', 'unconfirmed'  # the ``confidence`` evidence value


@dataclass(frozen=True)
class Entry:
    name: str  # with the CVE where one exists
    what: str  # what it is, what it needs, what it costs the victim
    steps: tuple  # ((title, command template, detail), ...): {ts} {nmap} {host} {port} {target} {url} are filled in
    fix: str
    ceiling: int  # the highest severity a proven result deserves
    cves: tuple = ()
    kind: str = 'vulnerability'  # 'exposure': testssl.sh reports a precondition (CBC suites, 64-bit blocks, HTTP compression), not an exploit
    read: tuple = ()  # (how a confirmation reads, how a clean answer reads)
    note: str = ''


def _s(title, command, detail=''):
    return (title, command, detail)


CATALOGUE = {
    # ------------------------------------------------------------------------------------------------ vulnerabilities
    'heartbleed': Entry(
        'Heartbleed (CVE-2014-0160)',
        'OpenSSL 1.0.1 to 1.0.1f answers a malformed heartbeat request with up to 64 KB of its own memory. Any client can ask, with no '
        'man-in-the-middle position and no credentials, and repeat it: private keys, session cookies and passwords have been recovered this way.',
        (_s('Run the one testssl.sh test', '{ts} --heartbleed {target}', 'It sends the malformed heartbeat and reads the reply.'),
         _s('Run the nmap script', '{nmap} --script ssl-heartbleed {host}', 'Prints VULNERABLE with the CVE when memory came back.'),
         _s('See whether the heartbeat extension is on at all', 'openssl s_client -connect {target} -servername {host} -tlsextdebug </dev/null 2>&1 | grep -i heartbeat',
            'No "heartbeat" line means the server cannot be vulnerable. A line alone is not proof.')),
        'Upgrade OpenSSL to 1.0.1g or later (any 1.0.2, 1.1.x or 3.x), restart every service that loads it, then treat the private key as '
        'stolen: reissue and revoke the certificate, and reset passwords and sessions that crossed this server. Behind a load balancer or '
        'appliance, patch that device; the vendor ships its own fix.',
        CRITICAL, ('CVE-2014-0160',),
        read=('testssl.sh or nmap says VULNERABLE: the server returns memory.', 'testssl.sh says "not vulnerable", or the heartbeat extension is absent.')),
    'CCS': Entry(
        'OpenSSL CCS injection (CVE-2014-0224)',
        'A vulnerable OpenSSL accepts an early ChangeCipherSpec message and derives its session keys from an empty secret. A man-in-the-middle '
        'can then force weak keys and read or alter the traffic. It needs the attacker on the network path and a vulnerable OpenSSL on both the '
        'client and the server.',
        (_s('Run the nmap script', '{nmap} --script ssl-ccs-injection {host}', 'Prints VULNERABLE only when the server accepted the early message.'),
         _s('Run the one testssl.sh test', '{ts} --ccs {target}', 'Read the CCS line: "VULNERABLE" is a result, "likely VULNERABLE" is a guess.'),
         _s('If a load balancer or CDN sits in front, test the server behind it', '{ts} --ccs <origin-address>:{port}',
            'Terminators often answer the probe oddly (a 0x00 byte, a reset) without running a vulnerable OpenSSL.')),
        'Upgrade OpenSSL on whatever terminates TLS: 0.9.8za, 1.0.0m or 1.0.1h and later (any 1.0.2, 1.1.x or 3.x), and restart the service. '
        'If a load balancer, CDN or appliance terminates TLS, patch or replace that device; the application server behind it is not the one '
        'answering.',
        HIGH, ('CVE-2014-0224',),
        read=('nmap says VULNERABLE, or testssl.sh says VULNERABLE (not "likely"): confirmed.', 'nmap says "NOT VULNERABLE" or testssl.sh says "not vulnerable": the server rejects the early message.'),
        note='"likely VULNERABLE" is testssl.sh guessing from an unexpected reply; a terminator in front often causes it.'),
    'ticketbleed': Entry(
        'Ticketbleed (CVE-2016-9244)',
        'F5 BIG-IP virtual servers with session tickets enabled echo back up to 31 bytes of uninitialised memory per resumed handshake. A remote '
        'client needs no man-in-the-middle position; repeated requests collect fragments of other sessions.',
        (_s('Run the one testssl.sh test', '{ts} --ticketbleed {target}', 'Experimental: it resumes with a short session ID and checks what the server echoes.'),),
        'Apply the F5 fix in advisory K05121675 for the BIG-IP version in use, or disable session tickets in the Client SSL profile (the vendor '
        'workaround) until it is installed.',
        HIGH, ('CVE-2016-9244',),
        read=('testssl.sh says VULNERABLE: the reply held bytes the client never sent.', 'testssl.sh says "not vulnerable", or the host is not an F5 BIG-IP.')),
    'ROBOT': Entry(
        'ROBOT, Bleichenbacher RSA padding oracle (CVE-2017-13099 and vendor CVEs)',
        'The server answers invalid RSA padding differently from valid padding, an oracle that lets an attacker decrypt recorded sessions and '
        'sign with the server key after many queries. It needs the RSA key-exchange cipher suites (TLS_RSA_*) and a vulnerable TLS stack, usually a '
        'load balancer or appliance. The CVE differs per product (for example CVE-2017-17382 Citrix, CVE-2017-13098 BouncyCastle).',
        (_s('Run the one testssl.sh test', '{ts} --robot {target}', 'It probes with malformed PKCS#1 messages and compares the answers.'),
         _s('See whether RSA key exchange is offered at all', '{nmap} --script ssl-enum-ciphers {host}',
            'Lines starting TLS_RSA_ are the exposed suites. Offered alone is not proof.')),
        'Apply the vendor patch for the TLS stack or appliance (the ROBOT advisory lists the product CVEs), and disable every TLS_RSA_* suite so '
        'only ECDHE or DHE suites remain; TLS 1.3 has none.',
        HIGH, ('CVE-2017-13099',),
        read=('testssl.sh says VULNERABLE: the oracle responds.', 'testssl.sh says "not vulnerable", or no RSA key-exchange suite is offered.')),
    'secure_client_renego': Entry(
        'Client-initiated TLS renegotiation (CVE-2011-1473)',
        'The server lets a client start renegotiation, and every one costs the server a full handshake and the client almost nothing. One client can '
        'exhaust the server CPU. It is a denial of service, not an exposure of data.',
        (_s('Run the one testssl.sh test', '{ts} --renegotiation {target}', 'It asks for renegotiation several times in a row.'),
         _s('Ask for it by hand with openssl', 'openssl s_client -connect {target} -servername {host} -tls1_2',
            'After the handshake type R and press Enter. A second handshake (the chain printed again) means it is accepted; "renegotiation failed" or a closed connection means it is refused.')),
        'Refuse client-initiated renegotiation in the TLS terminator (OpenSSL SSL_OP_NO_RENEGOTIATION or the product setting) or rate-limit it. '
        'TLS 1.3 has no renegotiation.',
        MEDIUM, ('CVE-2011-1473',),
        read=('The handshake repeats: renegotiation is accepted.', '"renegotiation failed" or a closed connection: refused.')),
    'CRIME_TLS': Entry(
        'CRIME, TLS compression (CVE-2012-4929)',
        'The server negotiates TLS-level compression. An attacker who sees the encrypted traffic and can make the victim browser send requests '
        'recovers secrets such as a session cookie from the changing record sizes. Current browsers no longer offer TLS compression, which limits '
        'it to old clients.',
        (_s('Run the one testssl.sh test', '{ts} --crime {target}', 'It offers compression and reports whether the server selects it.'),
         _s('Offer compression with openssl', 'openssl s_client -connect {target} -servername {host} -comp </dev/null 2>&1 | grep -i compression',
            'Needs an OpenSSL built with zlib. "Compression: zlib" means it was negotiated; "NONE" means it was not.')),
        'Turn TLS compression off (OpenSSL SSL_OP_NO_COMPRESSION; Apache SSLCompression off; most current builds default to off).',
        MEDIUM, ('CVE-2012-4929',),
        read=('testssl.sh says VULNERABLE: compression is negotiated.', 'testssl.sh says "not vulnerable", or openssl shows "Compression: NONE".')),
    'POODLE_SSL': Entry(
        'POODLE, SSLv3 CBC padding oracle (CVE-2014-3566)',
        'SSLv3 CBC padding is not authenticated. An attacker who sits on the network path and can make the victim browser send many requests '
        'recovers cookie bytes one at a time. It needs SSLv3 offered and a client that can be made to use it.',
        (_s('Run the one testssl.sh test', '{ts} --poodle {target}'),
         _s('Run the nmap script', '{nmap} --script ssl-poodle {host}', 'Prints VULNERABLE when SSLv3 CBC suites are accepted.'),
         _s('Try an SSLv3 handshake', 'openssl s_client -connect {target} -servername {host} -ssl3 </dev/null',
            'Works only if your OpenSSL still has SSLv3. A "Cipher is" line other than 0000 means the server accepted it.')),
        'Disable SSLv3 on the server (and everywhere the certificate is used). Support TLS 1.2 or later.',
        MEDIUM, ('CVE-2014-3566',),
        read=('SSLv3 CBC suites are accepted: confirmed.', 'SSLv3 is refused: not affected.')),
    'POODLE_TLS': Entry(
        'POODLE, TLS CBC padding oracle (CVE-2014-8730)',
        'Some TLS 1.0 to 1.2 implementations (load balancers in particular) do not check CBC padding after decryption, which gives the SSLv3 POODLE '
        'attack against TLS. Needs a man-in-the-middle and a vulnerable product.',
        (_s('Run the one testssl.sh test', '{ts} --poodle {target}', 'testssl.sh 3.2 does not implement this half of the check and prints no result for it.'),),
        'Apply the vendor patch of the TLS terminator (the 2014 advisories from F5, A10 and others), or drop CBC suites in favour of AES-GCM and ChaCha20.',
        MEDIUM, ('CVE-2014-8730',),
        read=('The vendor advisory lists the product and version as affected.', 'The product is patched or does not use CBC suites.'),
        note='testssl.sh 3.2 reports no result for this test, so cvENGINE normally never records it.'),
    'FREAK': Entry(
        'FREAK, export-grade RSA (CVE-2015-0204)',
        'The server accepts export-grade RSA cipher suites with 512-bit keys. A man-in-the-middle can downgrade a vulnerable client (old OpenSSL, Apple '
        'SecureTransport, pre-patch Android) to such a key, which can be factored in hours, and then read or alter the session.',
        (_s('Run the one testssl.sh test', '{ts} --freak {target}'),
         _s('Offer only export RSA suites', 'openssl s_client -connect {target} -servername {host} -cipher EXP </dev/null',
            'Current OpenSSL builds no longer contain export suites; use testssl.sh then. A completed handshake means they are accepted.')),
        'Remove every EXPORT cipher suite from the server configuration (cipher string !EXPORT). On OpenSSL servers also upgrade to 0.9.8zd, '
        '1.0.0p, 1.0.1k or later.',
        HIGH, ('CVE-2015-0204',),
        read=('testssl.sh says VULNERABLE: export RSA suites are accepted.', 'testssl.sh says "not vulnerable".')),
    'DROWN': Entry(
        'DROWN, SSLv2 cross-protocol attack (CVE-2016-0800)',
        'The server, or any other server that shares its RSA key or certificate, speaks SSLv2. An attacker with captured TLS traffic uses the SSLv2 '
        'oracle to decrypt it, for modest cost. The SSLv2 service can be a different port or a mail server using the same certificate.',
        (_s('Run the one testssl.sh test', '{ts} --drown {target}', 'It also prints the Censys link for other hosts that share the certificate.'),
         _s('Run the nmap script', '{nmap} --script sslv2-drown {host}', 'Names the vulnerable hosts that share the key, where it can tell.')),
        'Disable SSLv2 on every service that uses this key or certificate (web, mail, VPN). On OpenSSL upgrade to 1.0.2g or 1.0.1s, which turn SSLv2 off by default. '
        'Do not reuse the certificate on a service you cannot patch.',
        HIGH, ('CVE-2016-0800', 'CVE-2015-3197'),
        read=('SSLv2 is offered with usable ciphers: confirmed.', 'SSLv2 is not offered here and the key is not used by an SSLv2 service elsewhere.')),
    'LOGJAM': Entry(
        'Logjam, export-grade Diffie-Hellman (CVE-2015-4000)',
        'The server accepts DHE_EXPORT cipher suites with 512-bit Diffie-Hellman groups. A man-in-the-middle can downgrade a connection to one and break '
        'the exchange with precomputation, then read or alter the traffic. Separately, 1024-bit common primes are within reach of state-level attackers.',
        (_s('Run the one testssl.sh test', '{ts} --logjam {target}'),
         _s('Read the Diffie-Hellman group the server uses', '{nmap} --script ssl-dh-params {host}', 'Anything under 2048 bits is weak.')),
        'Remove DHE_EXPORT suites. Use a unique 2048-bit or larger group (openssl dhparam 2048), a standard ffdhe2048 or larger group, or ECDHE only.',
        HIGH, ('CVE-2015-4000',),
        read=('testssl.sh says VULNERABLE: DHE_EXPORT is accepted.', 'testssl.sh says "not vulnerable", and ssl-dh-params shows 2048 bits or more.')),
    'winshock': Entry(
        'Winshock, Windows Schannel remote code execution (MS14-066, CVE-2014-6321)',
        'A crafted TLS message makes Microsoft Schannel run attacker code before authentication, on servers without the November 2014 update '
        '(IIS, RDP, anything that terminates TLS with Schannel). testssl.sh cannot exploit it; it infers a missing patch from the cipher suites the server '
        'offers, so its result is a guess.',
        (_s('Run the one testssl.sh test', '{ts} --winshock {target}'),
         _s('On the Windows host, check the update', 'powershell -Command "Get-HotFix -Id KB2992611"',
            'Read-only. A row means installed; no row can also mean a later cumulative update replaced it, so compare the OS build with Microsoft\'s MS14-066 bulletin.')),
        'Install MS14-066 (KB2992611) or any later cumulative update for the Windows version, then restart. Windows 10 and Server 2016 and later are not affected.',
        CRITICAL, ('CVE-2014-6321',),
        read=('The host lacks KB2992611 or a later cumulative update.', 'The update, or a later cumulative update, is installed.'),
        note='testssl.sh only ever says "probably", "likely" or "seems" vulnerable here: never proof.'),
    'SWEET32': Entry(
        'SWEET32, 64-bit block ciphers (CVE-2016-2183, CVE-2016-6329)',
        'The server offers 3DES, IDEA or another cipher with 64-bit blocks. Over one long-lived connection carrying about 785 GB, a man-in-the-middle can '
        'recover plaintext such as a cookie from block collisions. It needs a very long session and a network position, so it is Low.',
        (_s('Run the one testssl.sh test', '{ts} --sweet32 {target}'),
         _s('List the offered suites', '{nmap} --script ssl-enum-ciphers {host}', 'Look for 3DES, DES-CBC3 and IDEA.')),
        'Remove the 64-bit block suites (cipher string !3DES:!IDEA); every modern client has AES-GCM or ChaCha20.',
        LOW, ('CVE-2016-2183', 'CVE-2016-6329'), kind='exposure',
        read=('A 64-bit block suite is offered: the precondition is present.', 'None is offered.')),
    'RC4': Entry(
        'RC4 cipher suites (CVE-2013-2566, CVE-2015-2808)',
        'The server accepts RC4, whose keystream is biased. An attacker on the network path who collects tens of millions of encrypted copies of the same '
        'secret (a cookie) can recover it. RFC 7465 forbids RC4 in TLS.',
        (_s('Run the one testssl.sh test', '{ts} --rc4 {target}'),
         _s('List the offered suites', '{nmap} --script ssl-enum-ciphers {host}', 'RC4 suites are listed by name.')),
        'Remove RC4 from the cipher list (!RC4) and use AES-GCM or ChaCha20 suites.',
        MEDIUM, ('CVE-2013-2566', 'CVE-2015-2808'),
        read=('An RC4 suite is accepted: confirmed.', 'None is offered.')),
    'BEAST': Entry(
        'BEAST (CVE-2011-3389)',
        'SSLv3 and TLS 1.0 use CBC with a predictable IV. A man-in-the-middle running script in the victim browser can decrypt cookies. Browsers have '
        'split records against it since 2012, so current clients are not exposed; testssl.sh reports the precondition (old protocol with CBC suites).',
        (_s('Run the one testssl.sh test', '{ts} --beast {target}'),
         _s('List the protocols and suites', '{nmap} --script ssl-enum-ciphers {host}', 'TLSv1.0 with CBC suites is the precondition.')),
        'Disable TLS 1.0 and SSLv3 and serve TLS 1.2 or later.',
        MEDIUM, ('CVE-2011-3389',), kind='exposure',
        read=('TLS 1.0 or SSLv3 is offered with CBC suites and nothing newer is preferred.', 'TLS 1.0 and SSLv3 are off.')),
    'LUCKY13': Entry(
        'Lucky Thirteen (CVE-2013-0169)',
        'A timing side channel in CBC padding checks. It needs an attacker on the network path and a very large number of sessions, and TLS libraries have '
        'been constant-time since 2013. testssl.sh flags it from the presence of CBC suites alone and measures no timing.',
        (_s('Run the one testssl.sh test', '{ts} --lucky13 {target}'),
         _s('List the offered suites', '{nmap} --script ssl-enum-ciphers {host}', 'CBC suites carry CBC in their name.')),
        'Keep the TLS library current (patched since 2013) and prefer AEAD suites (AES-GCM, ChaCha20); TLS 1.3 has no CBC.',
        LOW, ('CVE-2013-0169',), kind='exposure',
        read=('CBC suites are offered: the precondition is present.', 'No CBC suite is offered.')),
    'BREACH': Entry(
        'BREACH, HTTP compression (CVE-2013-3587)',
        'A response that is compressed, reflects attacker-chosen text and also contains a secret (a CSRF token) leaks the secret through its compressed size to '
        'an attacker who sees the traffic. testssl.sh sees only that HTTP compression is on; whether a page has all three ingredients is not checked.',
        (_s('Run the one testssl.sh test', '{ts} --breach {target}'),
         _s('See whether responses are compressed', "curl -sI -H 'Accept-Encoding: gzip, deflate, br' {url} | grep -i content-encoding",
            'A gzip, deflate or br line means compression is on.')),
        'Where a page carries a secret and reflects input, turn compression off for it, or mask the secret per request (as Django and Rails do for CSRF '
        'tokens), rate-limit, and set SameSite cookies.',
        MEDIUM, ('CVE-2013-3587',), kind='exposure',
        read=('Compression is on and a page mixes a secret with reflected input.', 'No compression, or no page mixes a secret with reflected input.')),
    # ------------------------------------------------------------------------------------------------ configuration
    'SSLv2': Entry(
        'SSLv2 offered',
        'SSL 2.0 is broken by design (no handshake protection, weak and export ciphers) and enables DROWN. No client needs it.',
        (_s('Run the protocol test', '{ts} -p {target}'),
         _s('Run the nmap script', '{nmap} --script sslv2 {host}', 'Lists the SSLv2 suites the server accepts.')),
        'Disable SSLv2 in the TLS configuration of the service (and of every service that shares its certificate).', CRITICAL,
        read=('The protocol line shows SSLv2 offered.', 'SSLv2 is "not offered".')),
    'SSLv3': Entry(
        'SSLv3 offered',
        'SSL 3.0 is deprecated (RFC 7568) and exposes POODLE (CVE-2014-3566) to a man-in-the-middle. Only ancient clients need it.',
        (_s('Run the protocol test', '{ts} -p {target}'),
         _s('Try an SSLv3 handshake', 'openssl s_client -connect {target} -servername {host} -ssl3 </dev/null',
            'Works only if your OpenSSL still has SSLv3. A completed handshake means it is offered.')),
        'Disable SSLv3 and serve TLS 1.2 or later.', HIGH, ('CVE-2014-3566',),
        read=('The protocol line shows SSLv3 offered.', 'SSLv3 is "not offered".')),
    'cipherlist_NULL': Entry(
        'NULL cipher suites offered',
        'The server accepts suites with no encryption at all. A client that picks one sends everything in clear, readable by anyone on the path.',
        (_s('Run the cipher category test', '{ts} -s {target}'),
         _s('Offer only NULL suites', "openssl s_client -connect {target} -servername {host} -cipher 'eNULL:@SECLEVEL=0' </dev/null",
            'A completed handshake with "Cipher is" naming NULL means it is accepted.')),
        'Remove the NULL suites (cipher string !eNULL).', CRITICAL,
        read=('The server completes a handshake with a NULL suite.', 'The handshake fails: no shared cipher.')),
    'cipherlist_aNULL': Entry(
        'Anonymous cipher suites offered',
        'The server accepts suites with no authentication (anonymous Diffie-Hellman). The client cannot tell the server from a man-in-the-middle.',
        (_s('Run the cipher category test', '{ts} -s {target}'),
         _s('Offer only anonymous suites', "openssl s_client -connect {target} -servername {host} -cipher 'aNULL:@SECLEVEL=0' </dev/null",
            'A completed handshake means they are accepted.')),
        'Remove the anonymous suites (cipher string !aNULL).', HIGH,
        read=('The server completes a handshake with an anonymous suite.', 'The handshake fails: no shared cipher.')),
    'cipherlist_EXPORT': Entry(
        'Export-grade cipher suites offered',
        'Export suites use 512-bit RSA or 40-bit keys that can be broken in minutes to hours. They are the precondition of FREAK and Logjam.',
        (_s('Run the cipher category test', '{ts} -s {target}'),
         _s('Offer only export suites', 'openssl s_client -connect {target} -servername {host} -cipher EXP </dev/null',
            'Current OpenSSL builds no longer contain export suites; use testssl.sh then.')),
        'Remove the export suites (cipher string !EXPORT).', HIGH, ('CVE-2015-0204', 'CVE-2015-4000'),
        read=('An export suite is accepted.', 'None is accepted.')),
    'cipherlist_LOW': Entry(
        'Low-strength cipher suites offered',
        'The server accepts suites with keys of 64 bits or less (single DES, RC2, MD5 MACs), which can be brute-forced.',
        (_s('Run the cipher category test', '{ts} -s {target}'),
         _s('List the offered suites', '{nmap} --script ssl-enum-ciphers {host}', 'Suites graded F or named DES, RC2 or RC4 are the weak ones.')),
        'Remove the weak suites (cipher string !LOW) and keep only AEAD suites.', MEDIUM,
        read=('A low-strength suite is accepted.', 'None is accepted.')),
    'cipherlist_3DES_IDEA': Entry(
        '3DES or IDEA cipher suites offered',
        'These have 64-bit blocks, so SWEET32 (CVE-2016-2183) applies to a very long session, and 3DES has at most 112 bits of effective strength.',
        (_s('Run the cipher category test', '{ts} -s {target}'),
         _s('Offer only 3DES', "openssl s_client -connect {target} -servername {host} -cipher '3DES:@SECLEVEL=0' </dev/null",
            'A completed handshake naming DES-CBC3 means 3DES is accepted.')),
        'Remove 3DES and IDEA (cipher string !3DES:!IDEA).', LOW, ('CVE-2016-2183',),
        read=('A 3DES or IDEA suite is accepted.', 'None is accepted.')),
    'secure_renego': Entry(
        'Insecure TLS renegotiation (CVE-2009-3555)',
        'The server does not support secure renegotiation (RFC 5746). A man-in-the-middle can inject plaintext in front of a victim session, for example a '
        'request that runs with the victim cookie or client certificate.',
        (_s('Run the one testssl.sh test', '{ts} --renegotiation {target}', 'Read the "Secure Renegotiation" line.'),
         _s('Read it from openssl', 'openssl s_client -connect {target} -servername {host} -tls1_2 </dev/null 2>&1 | grep -i renegotiation',
            '"Secure Renegotiation IS supported" is the good answer.')),
        'Upgrade the TLS library (OpenSSL 0.9.8m or later) and do not allow legacy renegotiation (Apache SSLInsecureRenegotiation off); TLS 1.3 has no renegotiation.',
        MEDIUM, ('CVE-2009-3555',),
        read=('openssl says "Secure Renegotiation IS NOT supported".', '"Secure Renegotiation IS supported".')),
    'FS': Entry(
        'No forward secrecy',
        'The server offers no ECDHE or DHE suite, so every session is encrypted with a key derived from its long-term RSA key. Whoever records traffic and '
        'later obtains that key can decrypt all of it.',
        (_s('Run the forward secrecy test', '{ts} -f {target}'),
         _s('Offer only forward-secret suites', 'openssl s_client -connect {target} -servername {host} -cipher ECDHE </dev/null',
            'A completed handshake means forward secrecy is offered; a handshake failure means it is not.')),
        'Enable ECDHE suites (for example ECDHE-RSA-AES128-GCM-SHA256) and prefer them; TLS 1.3 always has forward secrecy.', MEDIUM,
        read=('The ECDHE handshake fails or testssl.sh lists no forward-secret suite.', 'The ECDHE handshake completes.')),
    'fallback_SCSV': Entry(
        'TLS_FALLBACK_SCSV not supported',
        'Without it a man-in-the-middle can interrupt handshakes until a client retries with an older protocol (the POODLE downgrade). It matters only '
        'while the server still offers old protocols and the client retries downgrades; current browsers no longer do.',
        (_s('Run the one testssl.sh test', '{ts} --fallback {target}', 'Read the "Fallback SCSV" line.'),),
        'Update the TLS library (OpenSSL 1.0.1j, 1.0.0o, 0.9.8zc or later) or, better, turn off the old protocols so there is nothing to downgrade to.', MEDIUM,
        read=('testssl.sh says "NOT supported".', 'testssl.sh says "supported", or no old protocol is offered.')),
    'DH_groups': Entry(
        'Weak or unknown Diffie-Hellman group',
        'The server uses a Diffie-Hellman group below 2048 bits or one that is not a standard one. 1024-bit groups shared by many servers are within reach of '
        'state-level attackers (Logjam), and a small private group is breakable outright.',
        (_s('Run the forward secrecy test', '{ts} -f {target}', 'It prints the DH group and its size.'),
         _s('Read the group size', '{nmap} --script ssl-dh-params {host}', 'Under 2048 bits is weak.')),
        'Use a unique 2048-bit or larger group (openssl dhparam 2048), a standard ffdhe2048 or larger group, or only ECDHE suites.', HIGH, ('CVE-2015-4000',),
        read=('The group is under 2048 bits.', 'The group is 2048 bits or more, or no DHE suite is offered.')),
    NO_HANDSHAKE: Entry(
        'TLS listener does not negotiate',
        'The port accepts a connection but completes no TLS handshake with any protocol version for this server name, so no cipher or forward-secrecy result '
        'applies. A stale mapping (a CNAME to a service that no longer serves this name) or a listener that is not TLS looks like this.',
        (_s('Try a handshake', 'openssl s_client -connect {target} -servername {host} </dev/null', 'No certificate and "handshake failure" or "wrong version number" confirm it.'),
         _s('Run the protocol test', '{ts} -p {target}', 'Every protocol "not offered" confirms it.')),
        'Remove the name or the listener, or serve a certificate for the name.', LOW,
        read=('No handshake completes.', 'A handshake completes: the listener is TLS after all, rerun the audit.')),
}

TEST_LABELS = {  # "testssl.sh <label> test", as the finding page names the test
    'heartbleed': 'Heartbleed', 'CCS': 'CCS injection', 'ticketbleed': 'Ticketbleed', 'ROBOT': 'ROBOT', 'secure_client_renego': 'client-initiated renegotiation',
    'CRIME_TLS': 'CRIME (TLS compression)', 'POODLE_SSL': 'POODLE (SSLv3)', 'POODLE_TLS': 'POODLE (TLS)', 'FREAK': 'FREAK', 'DROWN': 'DROWN',
    'LOGJAM': 'Logjam', 'winshock': 'Winshock', 'SWEET32': 'SWEET32', 'RC4': 'RC4 cipher', 'BEAST': 'BEAST', 'LUCKY13': 'Lucky13', 'BREACH': 'BREACH',
    'SSLv2': 'SSLv2 protocol', 'SSLv3': 'SSLv3 protocol', 'cipherlist_NULL': 'NULL cipher', 'cipherlist_aNULL': 'anonymous cipher',
    'cipherlist_EXPORT': 'export cipher', 'cipherlist_LOW': 'low-strength cipher', 'cipherlist_3DES_IDEA': '3DES and IDEA cipher',
    'secure_renego': 'secure renegotiation', 'FS': 'forward secrecy', 'fallback_SCSV': 'TLS fallback SCSV', 'DH_groups': 'Diffie-Hellman group',
    NO_HANDSHAKE: 'protocol',
}
CHECK_ENTRY = {}  # tlsa_* check name -> catalogue id (filled below, as ``tls_audit.check_name`` makes them)


def check_name(test_id):
    """The hygiene check name of a testssl.sh test id (``tls_audit.check_name`` is the same function)."""
    return ('tlsa_' + re.sub(r'[^a-z0-9]+', '_', test_id.lower()).strip('_'))[:40]


for _id in CATALOGUE:
    CHECK_ENTRY[check_name(_id) if _id != NO_HANDSHAKE else 'tlsa_no_handshake'] = _id


def test_label(test_id):
    """"testssl.sh CCS injection test": how the finding page names the test (never the internal key)."""
    return f'testssl.sh {TEST_LABELS.get(test_id, str(test_id))} test'


def entry_for(check_or_test):
    """The catalogue entry for a ``tlsa_*`` check name or a testssl.sh test id, or None."""
    key = CHECK_ENTRY.get(check_or_test, check_or_test)
    return CATALOGUE.get(key)


# ------------------------------------------------------------------------------------------------ how sure a result is

def assess(test_id, text, testssl_severity, hard):
    """``(state, severity)`` of one vulnerability result. ``hard``: whether a VULNERABLE answer of this test is proof (``tls_audit.VULNS``).

    * ``proven``: the test answered plainly VULNERABLE, nothing says it is mitigated, testssl.sh rated it medium or higher and the test is one
      whose VULNERABLE answer is proof. The severity is testssl.sh's, held to the test's ceiling (CCS needs a man-in-the-middle: High).
    * ``possible``: "likely", "probably", "seems" or "potentially" vulnerable, or an odd reply the test cannot read: a heuristic, never proof.
    * ``exposure``: the precondition is present (CBC suites, 64-bit blocks, HTTP compression) or the result says it is mitigated; whether it is
      exploitable depends on clients or the application.

    Anything not proven is capped at Medium and at the test's own ceiling; the caller keeps testssl.sh's severity in the evidence."""
    entry = CATALOGUE.get(test_id)
    ceiling = entry.ceiling if entry else HIGH
    lower = str(text or '').lower()
    plain = lower.startswith('vulnerable')
    if hard and plain and 'mitigated' not in lower and testssl_severity >= MEDIUM and not (entry and entry.kind == 'exposure'):
        return PROVEN, min(testssl_severity, ceiling)
    state = EXPOSURE if (entry and entry.kind == 'exposure') or 'mitigated' in lower or plain else POSSIBLE
    return state, min(testssl_severity, UNPROVEN_CEILING, ceiling)


def confidence_of(state):
    return CONFIRMED if state == PROVEN else UNCONFIRMED


def title_for(test_id, state, where):
    """The finding title: plain about how sure it is."""
    entry = CATALOGUE[test_id]
    if state == PROVEN:
        return f'{entry.name} confirmed on {where}'
    if state == EXPOSURE:
        return f'{entry.name}: precondition present on {where}, not confirmed exploitable'
    return f'Possible {entry.name} on {where}, not confirmed'


# ------------------------------------------------------------------------------------------------ result strings

_HEX = re.compile(r'\bwith ([0-9A-Fa-f]{2})\b')
_CIPHERS = re.compile(r'Detected ciphers?:\s*(.+)$', re.I)
_COUNT = re.compile(r'with (\d+) ciphers', re.I)
_HIGHER = re.compile(r'higher protocols?\s+(.+?)\s*\(', re.I)
_HTTP_COMP = re.compile(r',\s*(.+?)\s+HTTP compression detected', re.I)
_LEAD = re.compile(r'^(likely|probably|seems|potentially)\b', re.I)
_BITS = re.compile(r'\((\d{3,5}) bits\)')
SENTENCES = {
    'heartbleed': 'The server answered a malformed heartbeat request, which carried no data, with data of its own: that is server memory leaking.',
    'ticketbleed': 'The server echoed bytes the client never sent in the session ID of a resumed-session reply: that is leaked server memory.',
}


CONFIG_OFFERED = {
    'SSLv2': 'The server offers SSLv2, a protocol that is broken by design.',
    'SSLv3': 'The server offers SSLv3, a deprecated protocol that POODLE breaks.',
    'cipherlist_NULL': 'The server accepts cipher suites that provide no encryption.',
    'cipherlist_aNULL': 'The server accepts cipher suites that provide no authentication.',
    'cipherlist_EXPORT': 'The server accepts export-grade cipher suites.',
    'cipherlist_LOW': 'The server accepts cipher suites of 64 bits or less.',
    'cipherlist_3DES_IDEA': 'The server accepts 3DES or IDEA cipher suites (64-bit blocks).',
}


def _unknown(text):
    return f'testssl.sh reported "{text}" for this test.'


def _unsure(word, what):
    return (f'testssl.sh reads {what} as {word.lower()} vulnerable, but that is an inference from an indirect sign and not a working exploit, so it is not confirmed.')


def describe_result(test_id, text):
    """One plain sentence for what testssl.sh said about ``test_id``. The raw string stays in the evidence, labelled "testssl.sh output"."""
    text = ' '.join(str(text or '').split())
    lower = text.lower()
    lead = _LEAD.match(text)
    unsure_word = lead.group(1) if lead else ''
    if test_id == 'CCS':
        if lower.startswith('likely vulnerable with'):
            found = _HEX.search(text)
            code = f'0x{found.group(1).upper()}' if found else 'an unexpected'
            return ('The server answered an early ChangeCipherSpec probe with ' + (f'a {code} byte' if found else code + ' reply') + ' instead of rejecting it. '
                    'testssl.sh reads that as likely vulnerable, but load balancers and TLS terminators often answer this way, so it is not proof.')
        if lower.startswith('likely vulnerable'):
            return ('The server answered an early ChangeCipherSpec probe with a bad_record_mac alert instead of the expected unexpected_message alert. '
                    'testssl.sh reads that as likely vulnerable, but it is a heuristic and not proof.')
        if lower.startswith('vulnerable'):
            return ('The server accepted an early ChangeCipherSpec message in the middle of the handshake and went on. That is the CVE-2014-0224 flaw: '
                    'the TLS stack that answered runs a vulnerable OpenSSL.')
    if test_id in SENTENCES and lower.startswith('vulnerable'):
        return SENTENCES[test_id]
    if test_id == 'ROBOT' and lower.startswith('vulnerable'):
        base = 'The server answers invalid RSA padding differently from valid padding (a Bleichenbacher oracle), which testssl.sh measured directly.'
        return base + (' The oracle is slow, so the attack would take impractically long.' if 'too long' in lower else '')
    if test_id == 'secure_client_renego' and lower.startswith('vulnerable'):
        return ('The server accepted client-initiated renegotiation several times in a row, so one client can make it repeat full handshakes until its CPU is exhausted.'
                if 'potential' not in lower else
                'The server accepted client-initiated renegotiation, which a client can repeat to make the server redo full handshakes. testssl.sh saw it accepted once.')
    if test_id == 'CRIME_TLS' and lower.startswith('vulnerable'):
        return ('The server negotiated TLS compression, the precondition of CRIME.' + (
            ' The port is not HTTP, so the attack, which needs injected web requests, probably does not apply.' if 'not using http' in lower else ''))
    if test_id == 'BREACH' and lower.startswith('potentially vulnerable'):
        found = _HTTP_COMP.search(text)
        return (f'The server compresses its HTTP responses ({found.group(1) if found else "gzip, deflate or similar"}). BREACH also needs a secret and '
                'attacker-chosen text in the same response, which testssl.sh does not check.')
    if test_id == 'POODLE_SSL' and lower.startswith('vulnerable'):
        return 'The server offers SSLv3 with CBC cipher suites, the combination the POODLE padding oracle attacks.'
    if test_id == 'FREAK' and lower.startswith('vulnerable'):
        return 'The server accepts export-grade RSA cipher suites (512-bit keys), which a man-in-the-middle can force on a vulnerable client.'
    if test_id == 'LOGJAM' and lower.startswith('vulnerable'):
        return 'The server accepts export-grade Diffie-Hellman cipher suites (512-bit groups), which a man-in-the-middle can force and break.'
    if test_id == 'LOGJAM' and 'no common prime' in lower:
        return 'The server accepts no export Diffie-Hellman, but its Diffie-Hellman group is small enough to be a risk.'
    if test_id == 'DROWN':
        if lower.startswith('vulnerable'):
            found = _COUNT.search(text)
            return (f'The server offers SSLv2 with {found.group(1) if found else "usable"} cipher suites, so its key can be attacked with DROWN, as can any '
                    'other service that shares this certificate key.')
        if 'sslv2 offered' in lower:
            return ('The server speaks SSLv2 but testssl.sh found no cipher it accepts. DROWN stays possible if the key is shared with an SSLv2 service '
                    'elsewhere, and CVE-2015-3197 applies on an old OpenSSL.')
    if test_id == 'winshock' and unsure_word:
        return ('testssl.sh infers from the cipher suites offered that the Schannel update MS14-066 is missing (' + unsure_word.lower() + ' vulnerable). '
                'It is a guess from the cipher list, not an exploit.')
    if test_id == 'SWEET32' and 'bit block' in lower:
        return 'The server offers cipher suites with 64-bit blocks (3DES, IDEA or similar)' + (' only under SSLv2' if 'sslv2 only' in lower else '') + '.'
    if test_id == 'RC4' and lower.startswith('vulnerable'):
        found = _CIPHERS.search(text)
        return 'The server accepts RC4 cipher suites' + (f' ({found.group(1).strip()})' if found else '') + '.'
    if test_id == 'BEAST' and lower.startswith('vulnerable'):
        found = _HIGHER.search(text)
        if found:
            return f'The server offers CBC cipher suites on TLS 1.0 or older but also supports {found.group(1)}, so clients that can use it avoid the attack.'
        return 'The server offers CBC cipher suites on TLS 1.0 or older and nothing newer; only a client without BEAST protection is exposed.'
    if test_id == 'LUCKY13' and lower.startswith('potentially vulnerable'):
        return ('The server offers CBC cipher suites. testssl.sh flags that from the suites alone; it measures no timing, and current TLS libraries are patched.')
    if test_id == 'secure_renego' and lower.startswith('vulnerable'):
        return 'The server does not support secure renegotiation (RFC 5746), so a man-in-the-middle can inject text into a session during renegotiation.'
    if test_id == 'fallback_SCSV':
        if lower.startswith('not supported'):
            return 'The server does not support TLS_FALLBACK_SCSV, so it cannot refuse a forced protocol downgrade.'
        if 'handshake failure' in lower:
            return 'The server answered a downgrade attempt with a handshake failure instead of the "inappropriate fallback" alert, so TLS_FALLBACK_SCSV is not implemented correctly.'
    if test_id == 'FS' and 'no ciphers supporting forward secrecy' in lower:
        return 'The server offers no cipher suite with forward secrecy (ECDHE or DHE).'
    if test_id == 'DH_groups':
        bits = _BITS.search(text)
        return f'The server uses the Diffie-Hellman group "{text}", which testssl.sh rates as weak' + (f' ({bits.group(1)} bits)' if bits else '') + '.'
    if test_id in CONFIG_OFFERED and lower.startswith('offered'):
        if 'no cipher' in lower:
            return f'The server speaks {test_id} but testssl.sh found no cipher suite it accepts.'
        return CONFIG_OFFERED[test_id]
    if test_id in ('SSLv2', 'SSLv3') and lower.startswith('vulnerable'):
        return f'The server speaks {test_id} and offers usable cipher suites.'
    # the generic forms of testssl.sh 3.2, "likely|probably|seems|potentially VULNERABLE" and "VULNERABLE (NOT ok)", with any detail after them
    if unsure_word and 'vulnerable' in lower:
        return _unsure(unsure_word, 'the server\'s answer')
    if lower.startswith('vulnerable'):
        detail = re.sub(r'^vulnerable\s*(\(not ok\))?\s*[,\-]*\s*', '', text, flags=re.I).strip(' ,.-')
        return 'testssl.sh\'s test reports the server as vulnerable' + (f' ({detail[:160]})' if detail else '') + '.'
    return _unknown(text)


# ------------------------------------------------------------------------------------------------ commands

def _fill(template, host, port):
    starttls = STARTTLS_PORTS.get(port)
    target = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    scheme_port = '' if port == 443 else f':{port}'
    url = 'https://' + (f'[{host}]' if ':' in host else host) + scheme_port + '/'
    nmap = 'nmap -Pn' + (' -6' if ':' in host else '') + (' -sV' if starttls else '') + f' -p {port}'
    ts = 'testssl.sh' + (f' --starttls {starttls}' if starttls else '')
    openssl_starttls = f' -starttls {starttls}' if starttls in ('smtp', 'imap', 'pop3', 'ftp') else ''
    command = template.format(ts=ts, nmap=nmap, host=confirm_guide._q(host), port=port, target=confirm_guide._q(target), url=confirm_guide._q(url))
    if confirm_guide._is_ip(host):
        command = command.replace(f' -servername {confirm_guide._q(host)}', '')  # no server name to send to an address
    if openssl_starttls:
        command = command.replace('openssl s_client ', 'openssl s_client' + openssl_starttls + ' ', 1)
    return command


def steps(test_id, host, port):
    """The confirm-it-yourself steps of one test for this host and port, in ``confirm_guide`` shape. ``[]`` when host or port is not valid."""
    entry = CATALOGUE.get(test_id)
    host, port = confirm_guide._host(host), confirm_guide._port(port)
    if entry is None or not host or not port:
        return []
    return [confirm_guide._step(title, detail, _fill(command, host, port)) for title, command, detail in entry.steps]


def split_where(where):
    """``(host, port)`` of a finding's ``host:port`` (an IPv6 address keeps its colons), port 0 when there is none."""
    host, _, last = str(where or '').rpartition(':')
    if not host or not last.isdigit():
        return str(where or ''), 0
    return host.strip('[]'), int(last)


def guide(check, evidence, where):
    """The confirm guide of a stored ``tlsa_*`` finding, in ``confirm_guide`` shape (the finding page draws it like a CVE match's), or None."""
    test_id = CHECK_ENTRY.get(check)
    entry = CATALOGUE.get(test_id) if test_id else None
    if entry is None:
        return None
    host, port = split_where(where)
    ev = evidence if isinstance(evidence, dict) else {}
    target = (f'[{host}]:{port}' if ':' in host else f'{host}:{port}') if host and port else where
    look = [{'label': 'The test', 'text': f'testssl.sh {ev.get("test") or test_id}'}]
    affected, clear = entry.read or ('The test reports the server as vulnerable.', 'The test reports it as not vulnerable.')
    return {'class': 'tls', 'class_label': 'testssl.sh TLS audit', 'headline': f'Confirm {entry.name} on {target}',
            'where': [{'label': 'TLS service', 'text': target}] if target else [], 'look_for': look,
            'steps': steps(test_id, host, port),
            'verdict': {'fixed': '', 'affected': affected, 'not_affected': clear,
                        'cant_tell': 'The connection fails, or a load balancer, CDN or WAF in front answers: test the server behind it directly.',
                        'notes': [entry.note] if entry.note else []},
            'fix': entry.fix,
            'notice': 'cvENGINE does not run these commands. They only read: run them yourself from a machine that is allowed to test this host.'}
