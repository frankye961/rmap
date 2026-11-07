# Example TCP scan with AI research

This recorded run uses `192.0.2.21` as an anonymized documentation address. Replace it with your authorized target. AI output is retained as recorded, including incomplete text; its CVE and exploit applicability claims are generated interpretations, not verified findings. Timings, search results, and model output vary between runs.

This historical output predates automatic HTTP probing on the additional candidate ports.

```bash
rmap --tcp --target 192.0.2.21 --ports 80,22,21,8080,443,111,139,445,2409,8000 --timeout-ms 1000 --ai
```

<details>
<summary>Recorded console output: scan measurements, AI interpretation, and web sources</summary>

```text
      \       /
   ___ \_____/ ___
  /   \(o   o)/   \
  \___/  ___  \___/
      \ (___) /
     __\_____/__
    / /       \ \
   (_/         \_)

  RRRRR   M   M    AAA    PPPPP
  R    R  MM MM   A   A   P    P
  R    R  M M M  AAAAAAA  P    P
  RRRRR   M   M  A     A  PPPPP
  R   R   M   M  A     A  P
  R    R  M   M  A     A  P

  v0.3.0 - Rust network scanner with optional AI interpretation.

Scan results for 192.0.2.21

PORT      STATE          SERVICE       ELAPSED  DETAIL
----------------------------------------------------------------------------------
80/tcp    open           http         96.60 ms  Server: Apache/2.4.68 (Debian)
22/tcp    open           ssh           3.44 ms  SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
21/tcp    open           -            55.19 ms  220 (vsFTPd 3.0.5)
8080/tcp  filtered       -          1000.83 ms  connection timed out
443/tcp   filtered       -          1000.26 ms  connection timed out
111/tcp   open           -            75.99 ms  read timed out
139/tcp   open           -            83.43 ms  read timed out
445/tcp   open           -            19.63 ms  read timed out
2409/tcp  filtered       -          1001.12 ms  connection timed out
8000/tcp  open           -            42.27 ms  read timed out

filtered = connection timed out; filtering is unconfirmed.

╭─ AI INTERPRETATION ───────────────────────────────────────────────────────
│  ## Observed services
│  - 80/tcp open — Apache/2.4.68 (Debian) [HTTP banner]
│  - 22/tcp open — OpenSSH_10.0p2 Debian-7+deb13u4 [SSH banner]
│  - 21/tcp open — vsFTPd 3.0.5 [FTP banner]
│  - 111, 139, 445, 8000/tcp open — no banner (read timeout); 8080/tcp
│  filtered. Service identity unconfirmed; not researched.
│
│  ## Possible CVEs (applicability + sources)
│  - **Apache 2.4.68**: Apache's own advisory page lists issues affecting
│  "2.4.0 through 2.4.68" (e.g., mod_heartmonitor NULL deref;
│  mod_session_cookie info exposure; mod_dav_fs integer overflow;
│  mod_userdir path equivalence). These are *fixed in a later release*, so
│  2.4.68 may be affected depending on module/config. Source:
│  https://httpd.apache.org/security/vulnerabilities_24.html . A Tenable
│  plugin references a "prior to 2.4.68" advisory set (CVE-2026-44119
│  mod_ssl OCSP over-read; CVE-2026-49975 HTTP/2 Bomb) — those affect
│  versions *before* 2.4.68, so likely not applicable to this host. Source:
│  https://www.tenable.com/plugins/nessus/319665 . Debian may backport
│  fixes; verify against Debian tr
│  - **vsFTPd 3.0.5**: CVE-2025-14242 — DoS via integer overflow in `ls`
│  parameter parsing; requires authenticated FTP access (CVSS 6.5, PR:L).
│  Debian tracker lists affected vsftpd source versions (3.0.3-12/-13/-13.1)
│  — applicability depends on the Debian package revision, not just the
│  3.0.5 banner. Sources:
│  https://access.redhat.com/security/cve/cve-2025-14242 ,
│  https://osv.dev/vulnerability/DEBIAN-CVE-2025-14242 ,
│  https://www.sentinelone.com/vulnerability-database/cve-2025-14242/ .
│  - **OpenSSH 10.0p2**: No specific CVE retrieved for this exact version.
│  Repology/CVE Details pages exist but returned no concrete applicable CVE
│  in snippets. Sources:
│  https://repology.org/project/openssh/cves?version=10.0p2 ,
│  https://www.cvedetails.com/version/1976097/Openbsd-Openssh-10.0.html . No
│  conclusion drawn.
│
│  ## Public exploit references (applicability + sources)
│  - vsftpd 3.0.3 Remote DoS — https://www.exploit-db.com/exploits/49719 —
│  reported version 3.0.3; not the observed 3.0.5, so likely not applicable.
│  - vsftpd 2.3.4 Backdoor (CVE-2011-2523) —
│  https://www.exploit-db.com/exploits/49757 — version 2.3.4; not applicable
│  to 3.0.5.
│  - vsftpd 2.0.5 CWD DoS — https://www.exploit-db.com/exploits/5814 —
│  version 2.0.5; not applicable.
│  - Apache 2.4.66 mod_http2 Double-Free DoS (CVE-2026-23918) —
│  https://www.exploit-db.com/exploits/52577 — reported 2.4.66; not the
│  observed 2.4.68.
│  - Apache 2.4.x Buffer Overflow (<2.4.51) —
│  https://www.exploit-db.com/exploits/51193 — not applicable to 2.4.68.
│  - No Exploit-DB entry retrieved matching vsFTPd 3.0.5 or Apache 2.4.68
│  exactly.
│
│  ## Verification
│  - Banners are self-reported and may be spoofed or patched; version
│  strings alone do not prove vulnerability.
│  - Confirm Apache module/config exposure and Debian package revision
│  (`dpkg -l apache2`) against the Debian tracker before concluding.
│  - For vsftpd, confirm the Debian package revision (CVE-2025-14242
│  applicability is revision-specific) and whether anonymous/authenticated
│  FTP is enabled.
│  - OpenSSH 10.0p2: no applicable CVE found in retrieved evidence — absence
│  of evidence, not proof of safety.
│  - Ports 111/139/445/8000 returned no banner; service identity and any
│  CVEs are unverified. 8080 filtered — no conclusion.
│  - No local advisory candidates were supplied; all findings above are
│  candidate-level from search snippets, not confirmed exploitation.
│
│  WEB RESEARCH
│  6 of at most 6 web searches performed; results are not exhaustive.
│  Information on source package apache2 - Security Bug Tracker
│  Source:
│  https://security-tracker.debian.org/tracker/source-package/apache2
│
│  Apache HTTP Server 2.4 vulnerabilities - The Apache HTTP Server Project
│  Source: https://httpd.apache.org/security/vulnerabilities_24.html
│
│  Apache Http Server : Security vulnerabilities, CVEs
│  Source:
│  https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/Apache-Http-Server.html
│
│  Apache 2.4.x
│  Source: https://www.tenable.com/plugins/nessus/319665
│
│  Known vulnerabilities in vsftpd 3.0.5
│  Source: https://www.cybersecurity-help.cz/vdb/soft/vsftpd/vsftpd/3.0.5/
│
│  Vsftpd Project Vsftpd 3.0.5 Observation Footprint | Bitsight
│  Source: https://www.bitsight.com/groma-explorer/vsftpdproject/vsftpd/305
│
│  RHSA-2026:0605 - Security Advisory
│  Source: https://access.redhat.com/errata/RHSA-2026:0605
│
│  Cve
│  Source: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=vsftpd
│
│  Openbsd Openssh 10.0 security vulnerabilities, CVEs
│  Source:
│  https://www.cvedetails.com/version/1976097/Openbsd-Openssh-10.0.html
│
│  Cisco Bug: CSCws05129 - Vulnerabilities in openssh 10.0p2
│  Source: https://bst.cisco.com/quickview/bug/CSCws05129
│
│  openssh vulnerabilities - Repology
│  Source: https://repology.org/project/openssh/cves?version=10.0p2
│
│  Cve
│  Source: https://www.cve.org/CVERecord/SearchResults?query=openssh
│
│  vsftpd 3.0.3 - Remote Denial of Service - Multiple remote Exploit
│  Source: https://www.exploit-db.com/exploits/49719
│
│  Gopherd 3.0.5 - FTP Gateway Remote Overflow - Linux remote Exploit
│  Source: https://www.exploit-db.com/exploits/84
│
│  vsftpd 2.3.4 - Backdoor Command Execution - Unix remote Exploit
│  Source: https://www.exploit-db.com/exploits/49757
│
│  vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption - Linux
│  dos Exploit
│  Source: https://www.exploit-db.com/exploits/5814
│
│  CVE-2025-14242 - Red Hat Customer Portal
│  Source: https://access.redhat.com/security/cve/cve-2025-14242
│
│  CVE-2025-14242: vsftpd Denial of Service Vulnerability
│  Source:
│  https://www.sentinelone.com/vulnerability-database/cve-2025-14242/
│
│  OSV - Open Source Vulnerabilities
│  Source: https://osv.dev/vulnerability/DEBIAN-CVE-2025-14242
│
│  Apache HTTP Server 2.4.66 - 'mod_http2' Double-Free Denial of Service -
│  Multiple webapps Exploit
│  Source: https://www.exploit-db.com/exploits/52577
│
│  Apache 2.4.x - Buffer Overflow - Multiple webapps Exploit
│  Source: https://www.exploit-db.com/exploits/51193
│
│  Apache 2.4.17
│  Source: https://www.exploit-db.com/exploits/46676
│
│  Apache
│  Source: https://www.exploit-db.com/exploits/42745
│
│  Candidate matches require manual verification, including vendor fixes.
```

</details>
