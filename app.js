const doors = [
  {
    day: 1,
    title: 'Recon & Scope',
    topic: 'Footprinting und Angriffsfläche verstehen',
    shortDesc: 'Passive & aktive Aufklärung: Ziele identifizieren, bevor der erste Scan läuft',
    tools: ['whois', 'nslookup', 'shodan.io', 'theHarvester', 'recon-ng', 'amass'],
    realWorld: 'Jeder Pentest beginnt hier: OSINT sammeln, Scope definieren, Attack Surface kartieren',
    lesson: {
      title: 'Was ist Reconnaissance?',
      story: [
        'Reconnaissance (Aufklärung) ist der erste und wichtigste Schritt eines jeden Penetrationstests. Es geht darum, so viele Informationen wie möglich über das Zielsystem zu sammeln, bevor der eigentliche Angriff beginnt.',
        'Dabei unterscheidet man zwischen passiver Recon (OSINT, ohne direkte Interaktion mit dem Ziel) und aktiver Recon (Portscans, DNS-Abfragen). Ziel ist es, die Angriffsfläche (Attack Surface) zu kartieren und schwache Punkte zu identifizieren.',
        'Der Scope definiert dabei die Grenzen des Tests: Was darf angegriffen werden und was ist tabu? Ohne klaren Scope bewegt man sich rechtlich auf dünnem Eis und riskiert, Systeme zu beschädigen, die nicht Teil des Tests sind.'
      ],
      use: 'Genutzt in jedem Pentest/Red-Team zu Beginn, um erlaubte Angriffsfläche und lohnende Ziele zu finden, bevor aktive Scans Lärm machen.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Befehl holt WHOIS-Daten für recon.example?',
      choices: [
        'whois recon.example',
        'ftp recon.example',
        'ping -b recon.example'
      ],
      answer: 'whois recon.example'
    }
  },
  {
    day: 2,
    title: 'OSINT Google-Fu',
    topic: 'Search-Dorks für versteckte Pfade',
    shortDesc: 'Google Dorks nutzen um Admin-Panels, Backups und Staging-Hosts zu finden',
    tools: ['Google (mit Operatoren)', 'DuckDuckGo', 'Bing', 'dorksearch.com', 'waybackmachine'],
    realWorld: 'Bug-Bounty-Standard: Passive Recon ohne Alarm, findet oft kritische Admin-Logins',
    lesson: {
      title: 'Was ist Google Hacking?',
      story: [
        'Google Hacking (oder Google Dorking) nutzt fortgeschrittene Suchoperatoren, um Informationen zu finden, die versehentlich öffentlich zugänglich gemacht wurden.',
        'Mit Operatoren wie "site:", "filetype:" oder "inurl:" lassen sich gezielt Login-Seiten, Konfigurationsdateien, Backups oder sensible Dokumente aufspüren, die von Suchmaschinen indexiert wurden.',
        'Diese Technik wird verwendet, um ohne aktive Scans (und damit oft unbemerkt) kritische Schwachstellen wie offene Admin-Panels oder geleakte Passwörter zu finden.'
      ],
      use: 'Nützlich in Bug-Bounties und OSINT-Phasen, wenn aktive Scans verboten sind; entdeckt schnell offene Verzeichnisse, Logins und Backups.'
    },
    game: {
      type: 'quiz',
      question: 'Welche Google-Dork findet Admin-Panels auf target.com?',
      choices: [
        'site:target.com inurl:admin',
        'target.com admin login',
        'filetype:admin target.com'
      ],
      answer: 'site:target.com inurl:admin'
    }
  },
  {
    day: 3,
    title: 'DNS-Enum',
    topic: 'Zoneninfos und Subdomains ermitteln',
    shortDesc: 'Zonentransfers testen, Subdomains brute-forcen, versteckte Hosts aufdecken',
    tools: ['dig', 'nslookup', 'host', 'subfinder', 'amass', 'DNSdumpster', 'fierce'],
    realWorld: 'Findet Dev/Staging-Server und interne APIs, die nicht öffentlich sein sollten',
    lesson: {
      title: 'Was ist DNS Enumeration?',
      story: [
        'DNS Enumeration ist der Prozess, alle DNS-Einträge einer Domain zu finden. Dazu gehören Subdomains (z.B. dev.example.com), Mailserver (MX) und Text-Einträge (TXT).',
        'Angreifer nutzen Tools, um Zonentransfers zu erzwingen oder Subdomains durch Brute-Force zu erraten. Oft finden sich so vergessene Entwicklungsserver oder interne Tools, die weniger gut geschützt sind als die Hauptseite.',
        'Das Verständnis der DNS-Struktur hilft, die Infrastruktur des Ziels zu verstehen und potenzielle Einstiegspunkte abseits der Hauptanwendung zu identifizieren.'
      ],
      use: 'Unverzichtbar bei External Pentests und Bug-Bounties, um versteckte Subdomains, Staging-Hosts und interne Namensräume aufzudecken.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Befehl führt einen DNS-Zonentransfer durch?',
      choices: [
        'dig AXFR target.com @10.10.10.53',
        'nslookup AXFR target.com',
        'ping target.com @10.10.10.53'
      ],
      answer: 'dig AXFR target.com @10.10.10.53'
    }
  },
  {
    day: 4,
    title: 'Portscan Basics',
    topic: 'Welche Dienste laufen wo?',
    shortDesc: 'Ports scannen, Services identifizieren, Versionen fingerprinting, CVEs mappen',
    tools: ['nmap', 'masscan', 'rustscan', 'unicornscan', 'naabu'],
    realWorld: 'Kern jeden Pentests: Offene Ports = Angriffsvektoren. Service-Versionen = CVE-Treffer',
    lesson: {
      title: 'Was ist ein Portscan?',
      story: [
        'Ein Portscan prüft, welche Netzwerkeingänge (Ports) auf einem System offen sind und welche Dienste dahinter lauschen (z.B. Webserver auf Port 80, SSH auf Port 22).',
        'Tools wie Nmap senden Pakete an das Ziel und analysieren die Antworten. Anhand der Reaktion kann oft nicht nur der offene Port, sondern auch die genaue Software-Version und das Betriebssystem erkannt werden.',
        'Dies ist essenziell, um bekannte Schwachstellen (CVEs) in veralteter Software zu finden. Ein offener, ungepatchter Dienst ist oft der einfachste Weg für einen Angreifer in das System.'
      ],
      use: 'Standard in Netzwerk-/Web-Pentests, um offene Dienste und Versionen zu kartieren und Exploit-Pfade (CVE-Mapping) abzuleiten.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Port ist der Standard für SSH?',
      choices: [
        '22',
        '21',
        '23'
      ],
      answer: '22'
    }
  },
  {
    day: 5,
    title: 'HTTP Anatomy',
    topic: 'Verben, Statuscodes, Header',
    shortDesc: 'HTTP-Requests verstehen: Methods (GET/POST/PUT), Status-Codes, Header manipulieren',
    tools: ['Burp Suite', 'curl', 'Postman', 'HTTPie', 'ZAP'],
    realWorld: 'API-Testing Grundlage: Header-Manipulation führt zu Auth-Bypasses und SSRF',
    lesson: {
      title: 'Wie funktioniert HTTP?',
      story: [
        'HTTP ist das Protokoll, über das Webbrowser und Server kommunizieren. Ein Request besteht aus einer Methode (GET, POST), Headern (Metadaten) und einem Body (Nutzdaten).',
        'Angreifer analysieren und manipulieren diese Pakete, um unerwartetes Verhalten zu provozieren. Sie ändern beispielsweise Header, um sich als anderer User auszugeben, oder injizieren Schadcode in Formularfelder.',
        'Das tiefe Verständnis von HTTP-Statuscodes (z.B. 200 OK, 403 Forbidden) und Headern ist die Basis für fast alle Web-Angriffe wie SQL-Injection oder XSS.'
      ],
      use: 'Wichtig in API-/Mobile-Tests, um Auth-Logik, CORS und gefährliche Methoden zu erkennen und daraus SSRF/Privilege-Eskalationen abzuleiten.'
    },
    game: {
      type: 'quiz',
      question: 'Welche Kombination beschreibt einen CORS-Fehler?',
      choices: [
        'Status 403 + fehlender Access-Control-Allow-Origin',
        'Status 301 + Location Header',
        'Status 200 + Content-Length'
      ],
      answer: 'Status 403 + fehlender Access-Control-Allow-Origin'
    }
  },
  {
    day: 6,
    title: 'Header Spotting',
    topic: 'Sichere Defaults erkennen',
    shortDesc: 'Security-Header analysieren: CSP, HSTS, X-Frame-Options prüfen und Fingerprints finden',
    tools: ['Burp Suite', 'SecurityHeaders.com', 'curl -I', 'Developer Tools (F12)'],
    realWorld: 'Fehlende Header = Clickjacking/XSS-Risiko. Server-Banner verraten alte Versionen',
    lesson: {
      title: 'Was sind Security Header?',
      story: [
        'Security Header sind Anweisungen des Servers an den Browser, wie er sich verhalten soll, um die Sicherheit zu erhöhen.',
        'Header wie "Content-Security-Policy" (CSP) oder "X-Frame-Options" verhindern, dass bösartige Skripte ausgeführt oder die Seite in fremde Frames geladen wird (Clickjacking).',
        'Das Fehlen dieser Header ist oft ein Indikator für mangelndes Sicherheitsbewusstsein. Tools und Browser-Extensions helfen dabei, schnell zu prüfen, ob eine Seite nach aktuellen Standards gehärtet ist.'
      ],
      use: 'Typisch in Webapp- und Admin-Portal-Reviews, um fehlende Schutz-Header aufzudecken, die XSS/Clickjacking erleichtern und Angriffsfläche preisgeben.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Header gibt gefährliche Server-Versionsinformationen preis?',
      choices: [
        'X-Powered-By: PHP/5.6.9',
        'Content-Security-Policy: default-src \'self\'',
        'Strict-Transport-Security: max-age=63072000'
      ],
      answer: 'X-Powered-By: PHP/5.6.9'
    }
  },
  {
    day: 7,
    title: 'Sessions & Cookies',
    topic: 'Session-Hardening',
    shortDesc: 'Cookie-Flags setzen: HttpOnly, Secure, SameSite gegen Hijacking und CSRF',
    tools: ['Browser DevTools (Application Tab)', 'Burp Suite', 'EditThisCookie', 'Cookie-Editor'],
    realWorld: 'Cookie-Diebstahl via XSS wird mit HttpOnly blockiert. SameSite verhindert CSRF-Angriffe',
    lesson: {
      title: 'Was sind Session Cookies?',
      story: [
        'Session-Cookies sind kleine Datenschnipsel, die den User nach dem Login identifizieren. Wer den Cookie hat, hat die Identität des Users.',
        'Um Diebstahl zu verhindern, gibt es Flags: "HttpOnly" verbietet JavaScript den Zugriff (Schutz gegen XSS), "Secure" erzwingt HTTPS, und "SameSite" schränkt das Senden an Dritte ein (Schutz gegen CSRF).',
        'Ohne diese Schutzmaßnahmen können Angreifer Sessions übernehmen (Session Hijacking) und im Namen des Opfers Aktionen durchführen.'
      ],
      use: 'Einsatz bei Web-/Mobile-Apps mit Session-Cookies, um Hijacking und CSRF zu verhindern; zentral in Pentest- und Bug-Bounty-Reports.'
    },
    game: {
      type: 'quiz',
      question: 'Welche Cookie-Flags schützen am besten vor XSS und CSRF?',
      choices: [
        'HttpOnly; Secure; SameSite=Lax',
        'Secure; Path=/',
        'Domain=target.com'
      ],
      answer: 'HttpOnly; Secure; SameSite=Lax'
    }
  },
  {
    day: 8,
    title: 'CSRF-Schutz',
    topic: 'Tokens & Origins',
    shortDesc: 'Cross-Site Request Forgery verhindern: CSRF-Tokens validieren und Origin-Header prüfen',
    tools: ['CSRF PoC Generator', 'Burp Suite (CSRF PoC)', 'curl', 'Postman'],
    realWorld: 'Banking/Admin-Panels ohne CSRF-Schutz: Angreifer kann im Namen des Users agieren',
    lesson: {
      title: 'Was ist CSRF?',
      story: [
        'Cross-Site Request Forgery (CSRF) zwingt den Browser eines eingeloggten Opfers, ungewollte Aktionen auf einer vertrauenswürdigen Seite auszuführen.',
        'Dies funktioniert, weil Browser Cookies automatisch mitsenden. Der Schutz besteht aus CSRF-Tokens (zufällige Werte, die bei jedem Request geprüft werden) und der Prüfung des Origin-Headers.',
        'Ohne CSRF-Schutz könnte ein Angreifer beispielsweise das Passwort eines Users ändern, indem er ihn einfach auf eine präparierte Webseite lockt.'
      ],
      use: 'Relevant in allen Web-Apps mit Session-Cookies (Banking, Shops, Admin), um unerwünschte Aktionen durch fremde Seiten zu verhindern.'
    },
    game: {
      type: 'quiz',
      question: 'Was verhindert CSRF-Angriffe am effektivsten?',
      choices: [
        'CSRF-Token validieren + Origin-Header prüfen',
        'Nur HTTPS verwenden',
        'Session-Cookies setzen'
      ],
      answer: 'CSRF-Token validieren + Origin-Header prüfen'
    }
  },
  {
    day: 9,
    title: 'XSS Basics',
    topic: 'Reflected & Stored XSS',
    shortDesc: 'Cross-Site Scripting: JavaScript in Webseiten einschleusen, Cookies stehlen, Payloads bauen',
    tools: ['Burp Suite', 'XSS Hunter', 'BeEF', 'XSStrike', 'DOMPurify (Defense)'],
    realWorld: 'Häufigster Bug in Bug-Bounties. Ermöglicht Session-Hijacking und Account-Übernahme',
    lesson: {
      title: 'Was ist XSS?',
      story: [
        'Cross-Site Scripting (XSS) ermöglicht es Angreifern, bösartigen JavaScript-Code in die Webseiten anderer Nutzer einzuschleusen.',
        'Man unterscheidet zwischen Reflected XSS (Schadcode kommt direkt aus der URL zurück) und Stored XSS (Schadcode wird in der Datenbank gespeichert und jedem Besucher angezeigt).',
        'XSS ist extrem gefährlich, da der Code im Kontext des Opfers läuft. Angreifer können so Session-Cookies stehlen, Tastatureingaben mitlesen oder den User auf Phishing-Seiten umleiten.'
      ],
      use: 'Häufigster Web-Bug in Bug-Bounties/Pentests; genutzt für Session-Diebstahl, Phishing und Pivoting in Admin-Bereiche.'
    },
    game: {
      type: 'quiz',
      question: 'Welche Payload umgeht ein einfaches <script>-Blacklist?',
      choices: [
        '<img src=x onerror=alert(1)>',
        '<script>alert(1)</script>',
        '<bold>alert(1)</bold>'
      ],
      answer: '<img src=x onerror=alert(1)>'
    }
  },
  {
    day: 10,
    title: 'SQLi Login',
    topic: 'Auth-Bypass per Injection',
    shortDesc: 'SQL Injection nutzen um Login zu umgehen: Payloads craften, Datenbanken enumerieren',
    tools: ['sqlmap', 'Burp Suite', 'manual SQL payloads', 'NoSQLMap (für NoSQL)'],
    realWorld: 'Klassischer Einstiegspunkt: Auth-Bypass → Admin-Zugriff → Datenleak',
    lesson: {
      title: 'Was ist SQL Injection?',
      story: [
        'SQL Injection (SQLi) entsteht, wenn Benutzereingaben ungeprüft in Datenbankabfragen eingebaut werden.',
        'Ein Angreifer kann durch spezielle Zeichen (wie \' oder --) die Logik der Abfrage verändern. So lässt sich beispielsweise eine Passwortprüfung mit \' OR 1=1 -- einfach "wahr" machen und umgehen.',
        'Dies führt oft zum kompletten Datenverlust oder zur Übernahme von Admin-Accounts. Der wirksamste Schutz sind Prepared Statements, die Code und Daten strikt trennen.'
      ],
      use: 'Klassische Auth-Bypässe in Legacy-Apps und schwach geprüften Logins; oft Einstiegspunkt für Datenleaks und Account-Übernahmen.'
    },
    game: {
      type: 'quiz',
      question: 'Welche Payload umgeht eine SQL-Login-Authentifizierung?',
      choices: [
        "' OR 1=1 -- -",
        'admin"; DROP TABLE users; --',
        '<script>alert(1)</script>'
      ],
      answer: "' OR 1=1 -- -"
    }
  },
  {
    day: 11,
    title: 'Command Injection',
    topic: 'Shell-Metazeichen erkennen',
    shortDesc: 'OS Command Injection: Shell-Befehle einschleusen über ; | ` $()',
    tools: ['Burp Suite', 'Commix', 'manual payloads (;id, `whoami`, $(cat /etc/passwd))'],
    realWorld: 'Admin-Tools mit system()-Aufrufen = direkte Server-Übernahme',
    lesson: {
      title: 'Was ist Command Injection?',
      story: [
        'OS Command Injection tritt auf, wenn eine Webanwendung Benutzereingaben direkt an die System-Shell weitergibt.',
        'Angreifer nutzen Trennzeichen wie ";", "|" oder "&&", um eigene Befehle anzuhängen. Wenn eine App z.B. "ping [Eingabe]" ausführt, macht "ping 8.8.8.8; id" daraus zwei Befehle: erst den Ping, dann die Ausgabe der Benutzer-ID.',
        'Dies ist eine der kritischsten Schwachstellen, da sie oft zur vollständigen Übernahme des Servers führt. Entwickler sollten niemals Shell-Befehle mit User-Input zusammenbauen.'
      ],
      use: 'Gefährlich in Admin-Tools, IoT-Interfaces und Support-Panels, die Systembefehle exposen; führt schnell zu kompletter Serverübernahme.'
    },
    game: {
      type: 'quiz',
      question: 'Welches Zeichen kann OS Command Injection ermöglichen?',
      choices: [
        '; (Semikolon)',
        '/ (Slash)',
        '= (Gleichheitszeichen)'
      ],
      answer: '; (Semikolon)'
    }
  },
  {
    day: 12,
    title: 'Path Traversal',
    topic: 'Ausbrechen aus dem Webroot',
    shortDesc: 'Directory Traversal: Mit ../../../../ aus Webroot ausbrechen, Configs lesen',
    tools: ['Burp Suite', 'dotdotpwn', 'manual payloads (../, URL-encoded versions)'],
    realWorld: 'Download-Features oft anfällig: /etc/passwd, .env-Files, SSH-Keys lesbar',
    lesson: {
      title: 'Was ist Path Traversal?',
      story: [
        'Path Traversal (oder Directory Traversal) erlaubt den Zugriff auf Dateien und Verzeichnisse, die außerhalb des Web-Root-Ordners liegen.',
        'Durch die Eingabe von "../" (dot-dot-slash) navigiert der Angreifer im Dateisystem nach oben. So können sensible Systemdateien wie "/etc/passwd" oder Konfigurationsdateien mit Passwörtern ausgelesen werden.',
        'Der Fehler liegt meist in fehlender Validierung von Dateinamen. Anwendungen sollten Dateipfade immer normalisieren und sicherstellen, dass sie im erlaubten Verzeichnis bleiben.'
      ],
      use: 'Typisch bei Download-/Log-View-Funktionen und schlecht geprüften File-Readern; dient oft als erster Schritt, um Secrets und Konfigurationen zu stehlen.'
    },
    game: {
      type: 'quiz',
      question: 'Was zeigt eine erfolgreiche Path Traversal Attack?',
      choices: [
        'Zugriff auf Dateien außerhalb des Webroot wie /etc/passwd',
        'SQL-Datenbank-Zugriff',
        'Cross-Site Scripting'
      ],
      answer: 'Zugriff auf Dateien außerhalb des Webroot wie /etc/passwd'
    }
  },
  {
    day: 13,
    title: 'File Upload',
    topic: 'Filter umgehen',
    shortDesc: 'Unrestricted File Upload ausnutzen: Webshells hochladen, Extensions manipulieren',
    tools: ['Burp Suite', 'Weevely (Webshell)', 'manual crafted files (.php.jpg, magic bytes)'],
    realWorld: 'CMS/Support-Portale: Ein hochgeladenes shell.php = vollständige Serverkontrolle',
    lesson: {
      title: 'Was ist Unrestricted File Upload?',
      story: [
        'Unsichere Datei-Uploads ermöglichen es Angreifern, ausführbaren Code (z.B. PHP-Skripte) auf den Server hochzuladen.',
        'Wenn der Server nur die Dateiendung prüft, kann ein Angreifer eine Datei wie "shell.php.jpg" hochladen oder den Content-Type fälschen. Wird die Datei dann ausgeführt, hat der Angreifer die Kontrolle.',
        'Sichere Uploads prüfen den tatsächlichen Dateiinhalt (Magic Bytes), benennen Dateien um und speichern sie idealerweise auf einem separaten Server ohne Ausführungsrechte.'
      ],
      use: 'Häufig bei CMS, Support-Portalen und Medien-Uploads; führt bei schwachen Checks zu Webshells und vollständiger Serverkontrolle.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Upload-Check ist am stärksten?',
      choices: [
        'Dateiendung blacklist',
        'Clientseitiger JS-Check',
        'Serverseitiger MIME + Magic-Byte + Extension-Allowlist'
      ],
      answer: 'Serverseitiger MIME + Magic-Byte + Extension-Allowlist'
    }
  },
  {
    day: 14,
    title: 'Passwort-Cracking',
    topic: 'Hashes & Wordlists',
    shortDesc: 'Hash-Cracking: Wordlists nutzen, Rules anwenden, Credentials knacken',
    tools: ['hashcat', 'john the ripper', 'hashid', 'rockyou.txt', 'crackstation.net'],
    realWorld: 'AD-Audits und Leaks: Schwache Passwörter in Stunden geknackt, Credential Stuffing möglich',
    lesson: {
      title: 'Was ist Passwort-Cracking?',
      story: [
        'Passwort-Cracking ist der Versuch, aus einem kryptografischen Hash (dem "Fingerabdruck" eines Passworts) das ursprüngliche Klartext-Passwort wiederherzustellen.',
        'Da Hashes nicht entschlüsselt werden können, nutzen Tools wie Hashcat riesige Wörterbücher und Regeln, um Millionen von Kombinationen zu hashen und mit dem Ziel-Hash zu vergleichen.',
        'Dies zeigt, warum komplexe, lange Passwörter wichtig sind: Kurze oder einfache Passwörter werden in Sekundenbruchteilen erraten.'
      ],
      use: 'Essentiell bei Incident Response, AD-Audits und Bug-Bounties, wenn Hash-Dumps oder Leaks auftauchen; zeigt Passwortschwächen und Reuse-Probleme.'
    },
    game: {
      type: 'quiz',
      question: 'Welches Tool wird für Hash-Cracking am häufigsten verwendet?',
      choices: [
        'hashcat',
        'nmap',
        'wireshark'
      ],
      answer: 'hashcat'
    }
  },
  {
    day: 15,
    title: 'Hash Verification',
    topic: 'Integrity-Checks',
    shortDesc: 'File-Integrity prüfen: SHA256/MD5-Hashes vergleichen gegen Manipulation',
    tools: ['sha256sum', 'md5sum', 'shasum', 'GPG', 'VirusTotal'],
    realWorld: 'DevOps/Supply-Chain: Firmware/Downloads auf Tampering prüfen vor Rollout',
    lesson: {
      title: 'Was ist Hash-Verifikation?',
      story: [
        'Hash-Verifikation dient dazu, die Integrität einer Datei sicherzustellen. Ein Hash-Wert (z.B. SHA256) ist wie ein digitaler Siegel.',
        'Wenn sich auch nur ein einziges Bit in der Datei ändert, ändert sich der gesamte Hash komplett. So lässt sich prüfen, ob ein Download manipuliert wurde oder Fehler enthält.',
        'In der Sicherheit ist dies essenziell, um sicherzustellen, dass Software nicht durch Angreifer modifiziert (Backdoored) wurde, bevor man sie installiert.'
      ],
      use: 'Einsatz in DevOps/IT-Betrieb und IR, um Supply-Chain-Angriffe und defekte Downloads zu erkennen, bevor sie auf viele Systeme verteilt werden.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Befehl prüft die SHA256-Integrität einer Datei?',
      choices: [
        'sha256sum image.iso',
        'md5 image.iso',
        'hash --check image.iso'
      ],
      answer: 'sha256sum image.iso'
    }
  },
  {
    day: 16,
    title: 'Traffic Capture',
    topic: 'Sniffen wie ein Ninja',
    shortDesc: 'Netzwerk-Traffic mitschneiden: Packets capturen, Wireshark-Analysen, Klartext finden',
    tools: ['tcpdump', 'Wireshark', 'tshark', 'ngrep', 'Ettercap (MITM)'],
    realWorld: 'Incident Response: kompromittierte Sessions rekonstruieren, Datenabfluss beweisen',
    lesson: {
      title: 'Was ist Traffic Capture?',
      story: [
        'Traffic Capture (Sniffing) bedeutet das Mitschneiden und Analysieren des Datenverkehrs in einem Netzwerk.',
        'Tools wie Wireshark zeichnen jedes Datenpaket auf. Wenn Verbindungen unverschlüsselt sind (HTTP, Telnet), können Passwörter und sensible Daten im Klartext mitgelesen werden.',
        'Für Administratoren ist dies wichtig zur Fehlersuche, für Angreifer ist es ein Weg, um an Zugangsdaten zu kommen. Verschlüsselung (TLS/HTTPS) ist der wichtigste Schutz dagegen.'
      ],
      use: 'Standardwerkzeug in Incident Response und Netzwerkanalyse, um Datenabfluss, Klartext-Zugänge und kompromittierte Sessions zu belegen.'
    },
    game: {
      type: 'quiz',
      question: 'Welches Tool wird zum Mitschneiden von Netzwerk-Traffic verwendet?',
      choices: [
        'tcpdump',
        'nmap',
        'hashcat'
      ],
      answer: 'tcpdump'
    }
  },
  {
    day: 17,
    title: 'SSH Hardening',
    topic: 'Absichern statt Brute-Force',
    shortDesc: 'SSH härten: Pubkey-Auth erzwingen, Fail2ban nutzen, Brute-Force verhindern',
    tools: ['SSH-Config', 'Fail2ban', 'Port-Knocking', 'Endlessh (Tarpit)'],
    realWorld: 'Exponierte Server: Tausende SSH-Brute-Force-Versuche täglich ohne Härtung',
    lesson: {
      title: 'Was ist SSH Hardening?',
      story: [
        'SSH ist der Standard für die Fernwartung von Servern. Standardmäßig ist es oft Ziel von automatisierten Brute-Force-Angriffen, die tausende Passwörter pro Sekunde probieren.',
        'Härtung (Hardening) bedeutet, diese Angriffsfläche zu minimieren: Deaktivierung des Passwort-Logins zugunsten von SSH-Keys, Ändern des Standard-Ports oder Nutzung von Tools wie Fail2ban.',
        'Ein gut gehärteter SSH-Server ist gegen reine Brute-Force-Angriffe praktisch immun, da kryptografische Schlüssel nicht erraten werden können.'
      ],
      use: 'Essentiell für Server-Härtung im Internet und in Cloud-VMs; senkt RDP/SSH-Brute-Force-Risiko und schützt sensible Admin-Zugänge.'
    },
    game: {
      type: 'quiz',
      question: 'Was senkt Brute-Force-Risiko am effektivsten?',
      choices: [
        'SSH-Port ändern auf 2222',
        'Fail2ban + PasswordAuthentication no',
        'Banner ändern'
      ],
      answer: 'Fail2ban + PasswordAuthentication no'
    }
  },
  {
    day: 18,
    title: 'Log Analysis',
    topic: 'Angriffe im Log sehen',
    shortDesc: 'Logs durchsuchen: Scanner erkennen, Geo-Anomalien finden, SIEM-Rules bauen',
    tools: ['grep/awk', 'SIEM (Splunk/ELK)', 'GoAccess', 'fail2ban logs', 'auth.log'],
    realWorld: 'SOC/Blue-Team: Scanner, Credential Stuffing und Account-Übernahmen früh blocken',
    lesson: {
      title: 'Was ist Log-Analyse?',
      story: [
        'Log-Analyse ist das systematische Auswerten von Protokolldateien, um Angriffe oder Anomalien zu erkennen.',
        'Angriffe hinterlassen Spuren: Tausende fehlgeschlagene Logins, seltsame User-Agents (wie "sqlmap") oder Zugriffe zu ungewöhnlichen Zeiten. SIEM-Systeme sammeln diese Logs zentral.',
        'Ohne Monitoring bleiben Einbrüche oft monatelang unbemerkt. Wer seine Logs liest, kann Angriffe oft stoppen, bevor Schaden entsteht.'
      ],
      use: 'Nötig im Blue-Teaming/SOC, um Scanner, Credential Stuffing und Account-Übernahmen früh zu erkennen und gezielt zu blocken.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher User-Agent deutet auf einen automatisierten Angriff hin?',
      choices: [
        'UA=sqlmap',
        'UA=Mozilla',
        'UA=Chrome'
      ],
      answer: 'UA=sqlmap'
    }
  },
  {
    day: 19,
    title: 'Reverse Shell',
    topic: 'Outbound Kontrolle',
    shortDesc: 'Shell zurückverbinden: bash /dev/tcp, nc, mkfifo für interaktive Shell nach RCE',
    tools: ['netcat (nc)', 'bash', 'python pty', 'socat', 'pwncat', 'msf meterpreter'],
    realWorld: 'Red-Team/Pentest: Nach RCE/Code Injection eine Shell holen für PrivEsc',
    lesson: {
      title: 'Was ist eine Reverse Shell?',
      story: [
        'Eine Reverse Shell ist eine Technik, bei der das Zielsystem (Opfer) aktiv eine Verbindung zum Angreifer aufbaut, anstatt umgekehrt.',
        'Dies umgeht oft Firewalls, da ausgehende Verbindungen häufiger erlaubt sind als eingehende. Der Angreifer erhält so eine Kommandozeile auf dem Server.',
        'Sie ist oft das erste Ziel nach einem erfolgreichen Exploit (z.B. Command Injection), um dauerhaften und interaktiven Zugriff auf das System zu erhalten.'
      ],
      use: 'Kernschritt in Red-Teaming/Pentests nach RCEs, um interaktiv zu arbeiten, PrivEsc vorzubereiten und persistente Zugänge aufzubauen.'
    },
    game: {
      type: 'quiz',
      question: 'Was ist der Zweck einer Reverse Shell?',
      choices: [
        'Interaktiven Zugriff nach RCE bekommen',
        'Passwörter hashen',
        'Netzwerk scannen'
      ],
      answer: 'Interaktiven Zugriff nach RCE bekommen'
    }
  },
  {
    day: 20,
    title: 'Buffer Overflow 101',
    topic: 'Crash to Shell',
    shortDesc: 'Memory Corruption: Stack überschreiben, EIP/RIP kontrollieren, Shellcode ausführen',
    tools: ['GDB', 'pwntools', 'pattern_create/offset', 'ROPgadget', 'checksec'],
    realWorld: 'Legacy-Software/CTFs: Memory-Corruption = RCE bei fehlenden Schutzmaßnahmen',
    lesson: {
      title: 'Was ist ein Buffer Overflow?',
      story: [
        'Ein Buffer Overflow entsteht, wenn ein Programm mehr Daten in einen Speicherbereich (Puffer) schreibt, als dieser fassen kann.',
        'Die überschüssigen Daten überschreiben benachbarte Speicherbereiche. Angreifer nutzen dies, um die Rücksprungadresse des Programms zu manipulieren und eigenen Schadcode auszuführen.',
        'Moderne Systeme haben Schutzmechanismen (ASLR, DEP), aber in alter Software oder IoT-Geräten ist dies immer noch eine häufige und kritische Schwachstelle.'
      ],
      use: 'Relevant bei Legacy-Diensten, Industrieanlagen und CTFs; zeigt, wie fehlende Memory-Schutzmaßnahmen zu Remote Code Execution führen.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Schutz verhindert das Ausführen von Stack-Daten?',
      choices: ['ASLR', 'DEP/NX', 'Canary'],
      answer: 'DEP/NX'
    }
  },
  {
    day: 21,
    title: 'JWT verstehen',
    topic: 'Tokens prüfen',
    shortDesc: 'JSON Web Tokens analysieren: alg:none testen, Signatures prüfen, Key-Rotation fordern',
    tools: ['jwt.io', 'Burp JWT extension', 'pyjwt', 'jwt_tool'],
    realWorld: 'Mobile/SPA-APIs: Falsch konfigurierte JWTs = Session-Hijacking und Replay-Angriffe',
    lesson: {
      title: 'Was sind JWTs?',
      story: [
        'JSON Web Tokens (JWT) sind ein offener Standard zur sicheren Übertragung von Informationen zwischen Parteien als JSON-Objekt.',
        'Sie bestehen aus Header, Payload und Signatur. Ein häufiger Angriff ist die Manipulation des Headers, um den Algorithmus auf "none" zu setzen, wodurch die Signaturprüfung umgangen wird.',
        'JWTs werden oft für die Authentifizierung in modernen Web-Apps genutzt. Wenn sie nicht korrekt validiert werden, können Angreifer ihre eigene Identität fälschen.'
      ],
      use: 'Weit verbreitet in Mobile-/SPA-/API-Auth; falsch konfigurierte JWTs erlauben Token-Replay oder Manipulation, daher Kernpunkt in App-Reviews.'
    },
    game: {
      type: 'quiz',
      question: 'Was bedeutet "alg:none" in einem JWT-Token?',
      choices: [
        'Ein gefährlicher Bypass: Signatur wird nicht geprüft',
        'Standard-Verschlüsselungsalgorithmus',
        'JWT ist abgelaufen'
      ],
      answer: 'Ein gefährlicher Bypass: Signatur wird nicht geprüft'
    }
  },
  {
    day: 22,
    title: 'Cloud Misconfigs',
    topic: 'Buckets & Policies',
    shortDesc: 'Cloud-Fehlkonfigurationen finden: Open S3 Buckets, IMDSv1, zu weite IAM-Policies',
    tools: ['aws-cli', 'ScoutSuite', 'Prowler', 'S3Scanner', 'CloudMapper'],
    realWorld: 'Cloud-Reviews: Offene Buckets = Datenleak, IMDS = Token-Diebstahl',
    lesson: {
      title: 'Was sind Cloud Misconfigs?',
      story: [
        'Cloud-Fehlkonfigurationen sind eine der häufigsten Ursachen für Datenlecks. Oft sind es einfache Fehler wie öffentlich zugängliche Speicher (S3 Buckets) oder zu weitreichende Berechtigungen (IAM).',
        'Angreifer scannen automatisiert nach offenen Buckets oder nutzen Dienste wie den Instance Metadata Service (IMDS), um temporäre Zugangsdaten zu stehlen.',
        'Das Prinzip der minimalen Rechte (Least Privilege) ist hier entscheidend: Jeder Dienst und jeder Nutzer sollte nur genau die Rechte haben, die er unbedingt braucht.'
      ],
      use: 'Typisch in Cloud-Reviews/Bug-Bounties: falsche Bucket-Policies und offene Metadata-Services führen direkt zu Datenabfluss und Token-Diebstahl.'
    },
    game: {
      type: 'quiz',
      question: 'Welcher Bucket-Policy-Eintrag ist gefährlich?',
      choices: [
        '{"Effect":"Deny","Principal":"*","Action":"s3:*"}',
        '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}',
        '{"Effect":"Allow","Principal":"account123","Action":"s3:ListBucket"}'
      ],
      answer: '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}'
    }
  },
  {
    day: 23,
    title: 'Mobile Interception',
    topic: 'APK & Traffic',
    shortDesc: 'Mobile-App-Hacking: APK dekompilieren, SSL-Pinning bypassen, API-Keys finden',
    tools: ['apktool', 'jadx', 'Frida', 'Objection', 'Burp Suite', 'MobSF'],
    realWorld: 'Mobile-Pentest: Hardcoded API-Keys, schwaches Pinning = Backend-Zugriff',
    lesson: {
      title: 'Was ist Mobile Interception?',
      story: [
        'Mobile Interception bezeichnet das Abfangen und Analysieren des Datenverkehrs zwischen einer mobilen App und ihrem Backend.',
        'Um HTTPS-Verkehr mitzulesen, müssen Sicherheitsmechanismen wie SSL-Pinning oft mit Tools wie Frida umgangen werden. So lassen sich API-Schlüssel oder Schwachstellen im Backend finden.',
        'Viele Apps vertrauen blind darauf, dass der Client "sicher" ist. Angreifer beweisen das Gegenteil, indem sie die App manipulieren und Anfragen fälschen.'
      ],
      use: 'Relevant für Mobile-App-Tests und Bug-Bounties: offenliegende API-Keys und schwache Pinning/Role-Checks geben direkten Zugang zu Backend-Funktionen.'
    },
    game: {
      type: 'quiz',
      question: 'Welches Tool wird verwendet, um SSL-Pinning in Android-Apps zu umgehen?',
      choices: [
        'Frida',
        'nmap',
        'Wireshark'
      ],
      answer: 'Frida'
    }
  },
  {
    day: 24,
    title: 'Finale CTF',
    topic: 'Alles kombinieren',
    shortDesc: 'CTF Kill-Chain: Recon → Exploit → Shell → PrivEsc → Root Flag',
    tools: ['nmap + NSE', 'metasploit', 'searchsploit', 'LinPEAS/WinPEAS', 'GTFOBins'],
    realWorld: 'Red-Team: Komplette Attack-Chain demonstrieren, nicht nur Einzelbugs',
    lesson: {
      title: 'Was ist ein CTF?',
      story: [
        'Capture The Flag (CTF) Wettbewerbe simulieren echte Hacking-Szenarien in einer sicheren Umgebung. Ziel ist es, "Flaggen" (Textstrings) zu finden, die den erfolgreichen Hack beweisen.',
        'Dabei werden alle gelernten Techniken kombiniert: Von der Aufklärung (Recon) über das Ausnutzen einer Schwachstelle (Exploit) bis hin zur Rechteausweitung (Privilege Escalation) auf Root-Ebene.',
        'CTFs sind das beste Training, um die Denkweise eines Angreifers zu verstehen und die komplette "Kill Chain" eines Angriffs praktisch durchzuspielen.'
      ],
      use: 'CTFs, Red-Team-Engagements und Lernlabore: Alles kombinieren, um komplette Kill-Chains zu bauen und den Impact nachvollziehbar zu zeigen.'
    },
    game: {
      type: 'quiz',
      question: 'Was bedeutet die nmap-Option "-sV"?',
      choices: [
        'Service-Version Detection',
        'Scan Verbose',
        'Skip Verification'
      ],
      answer: 'Service-Version Detection'
    }
  },
  {
    day: 25,
    title: 'Bonus: KI Hacking',
    topic: 'LLM-Angriffsfläche & Prompt Injection',
    shortDesc: 'LLMs angreifen: Prompt Injection, System-Prompts extrahieren, Guardrails umgehen',
    tools: ['Manual Prompts', 'Burp Suite (API)', 'LLM Security Tools', 'Garak'],
    realWorld: 'Chatbot/AI-Features: Prompt Injection = Data Leaks, unerwünschte Aktionen',
    lesson: {
      title: 'Was ist Prompt Injection?',
      story: [
        'KI-Hacking (oder LLM Security) beschäftigt sich mit den Schwachstellen von großen Sprachmodellen. Eine Hauptgefahr ist "Prompt Injection".',
        'Dabei versucht der Angreifer, durch geschickte Eingaben die Sicherheitsregeln der KI zu umgehen, um sie dazu zu bringen, interne Daten preiszugeben oder schädliche Inhalte zu generieren.',
        'Da KIs immer tiefer in Systeme integriert werden, wird der Schutz vor solchen Manipulationen immer wichtiger.'
      ],
      use: 'Relevant bei allen LLM-Features in Produkten (Chatbots, Assistenten, Agenten), um Prompt Injection, Data Leaks und unerwünschte Aktionen aufzudecken.'
    },
    game: {
      type: 'quiz',
      question: 'Was beschreibt eine Prompt Injection am besten?',
      choices: [
        'SQL-Kommandos in Formularfelder einschleusen',
        'Das Modell über Eingaben dazu bringen, Systemregeln zu ignorieren oder interne Daten auszugeben',
        'Ports scannen, um offene Dienste zu finden'
      ],
      answer: 'Das Modell über Eingaben dazu bringen, Systemregeln zu ignorieren oder interne Daten auszugeben'
    }
  },
  {
    day: 26,
    title: 'Bonus: KI Abuse',
    topic: 'Model Stealing & Guardrails umgehen',
    shortDesc: 'Advanced AI-Attacks: Model Extraction, Jailbreaks, Output-Manipulation testen',
    tools: ['API Testing Tools', 'Rate-Limit-Scanner', 'Jailbreak Prompts', 'OWASP LLM Top 10'],
    realWorld: 'AI-Security-Audits: Guardrails umgehen, IP stehlen, schädliche Outputs provozieren',
    lesson: {
      title: 'Was ist KI-Missbrauch?',
      story: [
        'KI-Missbrauch umfasst Angriffe wie Model Stealing (Nachbau eines Modells durch viele Anfragen) oder das Umgehen von ethischen Schutzmechanismen (Jailbreaks).',
        'Angreifer nutzen KIs auch, um bessere Phishing-Mails zu schreiben oder Malware zu generieren. Auf der anderen Seite müssen KI-Systeme gegen Missbrauch gehärtet werden.',
        'Sicherheitsmaßnahmen umfassen Rate-Limiting, Output-Filterung und ständiges Monitoring, um Anomalien im Verhalten der KI zu erkennen.'
      ],
      use: 'Einsatz in KI-Sicherheitsaudits und Red-Teaming von LLM/ML-Features, um Guardrails, IP-Schutz und Data Leakage zu prüfen.'
    },
    game: {
      type: 'quiz',
      question: 'Was ist die beste Defense gegen Prompt Injection?',
      choices: [
        'Input/Output-Filtering + Kontext-Isolation',
        'Längere Passwörter verwenden',
        'SSL aktivieren'
      ],
      answer: 'Input/Output-Filtering + Kontext-Isolation'
    }
  },
  {
    day: 27,
    title: 'Bonus: Docker Breakout',
    topic: 'Container Escape',
    shortDesc: 'Aus dem Container ausbrechen: Privileged Mode, Capabilities, Mounts',
    tools: ['CDK', 'Deepce', 'mount', 'capsh', 'docker.sock'],
    realWorld: 'Cloud-Native Hacking: Wer den Container übernimmt, will auf den Host',
    lesson: {
      title: 'Was ist ein Docker Breakout?',
      story: [
        'Container sollen Anwendungen isolieren. Ein Breakout passiert, wenn ein Angreifer aus dieser Isolation ausbricht und Zugriff auf das Host-System erlangt.',
        'Häufige Ursachen sind falsch konfigurierte Container (z.B. "privileged mode"), gemountete Docker-Sockets oder unsichere Kernel-Capabilities.',
        'Ein erfolgreicher Breakout bedeutet oft die Kompromittierung des gesamten Clusters oder Servers.'
      ],
      use: 'Wichtig in Cloud-Security-Audits und Kubernetes-Pentests; zeigt die Gefahren von zu vielen Rechten für Container.'
    },
    game: {
      type: 'quiz',
      question: 'Welches Flag ist ein Sicherheitsrisiko beim Starten von Docker-Containern?',
      choices: [
        '--privileged',
        '--rm',
        '--name'
      ],
      answer: '--privileged'
    }
  },
  {
    day: 28,
    title: 'Bonus: API Security',
    topic: 'Broken Object Level Auth',
    shortDesc: 'API-Hacking: IDORs finden, Mass Assignment, Swagger-Files analysieren',
    tools: ['Postman', 'Burp Suite', 'Kiterunner', 'Arjun'],
    realWorld: 'Datenlecks durch IDOR: Einfach ID in der URL hochzählen und fremde Daten sehen',
    lesson: {
      title: 'Was ist BOLA / IDOR?',
      story: [
        'Broken Object Level Authorization (BOLA), oft auch IDOR genannt, ist die häufigste API-Schwachstelle.',
        'Sie tritt auf, wenn eine API den Zugriff auf Objekte (z.B. Rechnungen, Profile) nur anhand einer ID erlaubt, ohne zu prüfen, ob der anfragende Nutzer berechtigt ist.',
        'Angreifer können einfach IDs in der URL ändern (z.B. /user/123 zu /user/124), um auf fremde Daten zuzugreifen.'
      ],
      use: 'Nummer 1 in den OWASP API Top 10; extrem häufig in modernen Apps und Microservices zu finden.'
    },
    game: {
      type: 'quiz',
      question: 'Was ist ein typisches Zeichen für eine IDOR-Schwachstelle?',
      choices: [
        'Zugriff auf fremde Daten durch Ändern einer ID in der URL',
        'SQL-Fehlermeldungen',
        'Langsames Laden der Seite'
      ],
      answer: 'Zugriff auf fremde Daten durch Ändern einer ID in der URL'
    }
  },
  {
    day: 29,
    title: 'Bonus: Social Eng.',
    topic: 'Human Hacking',
    shortDesc: 'Faktor Mensch: Phishing, Pretexting, USB-Drops, Vishing',
    tools: ['GoPhish', 'SET (Social Engineer Toolkit)', 'Telefon', 'Fake-Login-Pages'],
    realWorld: 'Der einfachste Weg rein: Warum Firewall hacken, wenn der Admin das Passwort verrät?',
    lesson: {
      title: 'Was ist Social Engineering?',
      story: [
        'Social Engineering zielt nicht auf technische Schwachstellen, sondern auf menschliche Fehler und Manipulation.',
        'Angreifer nutzen psychologische Tricks (Dringlichkeit, Autorität, Hilfsbereitschaft), um Opfer zur Herausgabe von Passwörtern oder zum Ausführen von Schadsoftware zu bewegen.',
        'Phishing-Mails sind der bekannteste Vektor, aber auch Anrufe (Vishing) oder physischer Zugang (Tailgating) gehören dazu.'
      ],
      use: 'Oft der Startpunkt für Red-Team-Operationen; umgeht technische Sicherheitsmaßnahmen durch Ausnutzung des Vertrauens.'
    },
    game: {
      type: 'quiz',
      question: 'Was ist ein häufiges Merkmal von Phishing-Mails?',
      choices: [
        'Erzeugung von künstlichem Zeitdruck',
        'Korrekte persönliche Anrede',
        'Digitale Signatur'
      ],
      answer: 'Erzeugung von künstlichem Zeitdruck'
    }
  },
  {
    day: 30,
    title: 'Bonus: WiFi Hacking',
    topic: 'WPA2 & Evil Twins',
    shortDesc: 'Wireless Attacks: Handshakes capturen, Deauth-Attacken, Rogue APs',
    tools: ['aircrack-ng', 'wifite', 'kismet', 'EAPHammer', 'Flipper Zero'],
    realWorld: 'Vor Ort: Ins interne Netz kommen via Gäste-WLAN oder gefälschtem Access Point',
    lesson: {
      title: 'Wie funktioniert WiFi-Hacking?',
      story: [
        'WLAN-Netzwerke sind oft das Tor ins interne Firmennetz. Angreifer versuchen meist, den "Handshake" zwischen Client und Router mitzuschneiden.',
        'Dieser Handshake enthält den Hash des WLAN-Passworts, der dann offline geknackt werden kann. Eine andere Methode sind "Evil Twin"-Angriffe, bei denen ein legitimer Access Point geklont wird.',
        'Gegenmaßnahmen sind starke Passwörter und Zertifikats-basierte Authentifizierung (WPA2/3-Enterprise).'
      ],
      use: 'Physische Pentests und Red-Teaming; ermöglicht Zugang zum Netzwerk ohne Kabelverbindung.'
    },
    game: {
      type: 'quiz',
      question: 'Was wird benötigt, um ein WPA2-Passwort offline zu knacken?',
      choices: [
        'Der 4-Way-Handshake',
        'Die SSID',
        'Die MAC-Adresse'
      ],
      answer: 'Der 4-Way-Handshake'
    }
  },
  {
    day: 31,
    title: 'Bonus: Mindset',
    topic: 'White Hat vs. Black Hat',
    shortDesc: 'Ethik & Karriere: Responsible Disclosure, Bug Bounties, Zertifizierungen',
    tools: ['HackerOne', 'Intigriti', 'OSCP', 'HTB', 'TryHackMe'],
    realWorld: 'Vom Hobby zum Beruf: Wie man legal hackt und Unternehmen sicherer macht',
    lesson: {
      title: 'Das Hacker-Mindset',
      story: [
        'Hacking ist mehr als nur Technik – es ist eine Denkweise. Es geht darum, Systeme zu verstehen, Grenzen zu testen und kreative Lösungen zu finden.',
        'Der Unterschied zwischen Kriminellen (Black Hats) und Sicherheitsforschern (White Hats) liegt allein in der Erlaubnis und der Ethik.',
        'Responsible Disclosure bedeutet, gefundene Lücken erst dem Hersteller zu melden, damit dieser sie schließen kann, bevor sie veröffentlicht werden.'
      ],
      use: 'Der Abschluss des Kalenders: Nutze dein Wissen, um das Internet sicherer zu machen. Hacking is not a crime, if you have permission.'
    },
    game: {
      type: 'quiz',
      question: 'Was unterscheidet einen White Hat von einem Black Hat?',
      choices: [
        'Die Erlaubnis des Eigentümers',
        'Die verwendeten Tools',
        'Das Betriebssystem'
      ],
      answer: 'Die Erlaubnis des Eigentümers'
    }
  }
];

const calendarEl = document.getElementById('calendar');
const modal = document.getElementById('modal');
const modalDay = document.getElementById('modal-day');
const modalTitle = document.getElementById('modal-title');
const modalTopic = document.getElementById('modal-topic');
const lessonEl = document.getElementById('lesson');
const gameEl = document.getElementById('game');
const closeModalBtn = document.getElementById('close-modal');
const progressFill = document.getElementById('progress-fill');
const progressCount = document.getElementById('progress-count');
const terminalFeed = document.getElementById('terminal-feed');

const storageKey = 'hacker-advent-solved';
const solved = new Set(JSON.parse(localStorage.getItem(storageKey) || '[]'));
let currentDoorIndex = 0;

function saveSolved() {
  localStorage.setItem(storageKey, JSON.stringify([...solved]));
}

function logLine(message) {
  const line = document.createElement('div');
  const now = new Date().toISOString().split('T')[1].slice(0, 8);
  line.textContent = `[${now}] ${message}`;
  terminalFeed.appendChild(line);
  terminalFeed.scrollTop = terminalFeed.scrollHeight;
  if (terminalFeed.children.length > 80) terminalFeed.removeChild(terminalFeed.firstChild);
}

function isSolved(day) {
  return solved.has(day);
}

function isLocked(day) {
  const now = new Date();
  const currentMonth = now.getMonth(); // 0-11, Dec is 11
  const currentDay = now.getDate();

  // If it's not December yet (month < 11), everything is locked
  if (currentMonth < 11) return true;
  // If it's past December (month > 11, e.g. Jan), everything is unlocked (optional, or keep locked?)
  // Let's assume we want them open after Dec.
  if (currentMonth > 11) return false;

  // It is December: lock if day is in the future
  return day > currentDay;
}

function markSolved(day) {
  if (solved.has(day)) return;
  solved.add(day);
  saveSolved();
  updateProgress();
  renderCalendar();
  logLine(`Tor ${day} geknackt.`);
}

function updateProgress() {
  const done = solved.size;
  progressFill.style.width = `${(done / doors.length) * 100}%`;
  progressCount.textContent = `${done} / ${doors.length}`;
}

function renderCalendar() {
  calendarEl.innerHTML = '';
  doors.forEach((door, idx) => {
    const locked = isLocked(door.day);
    const card = document.createElement('article');
    card.className = 'door' + (isSolved(door.day) ? ' completed' : '') + (locked ? ' locked' : '');
    card.tabIndex = locked ? -1 : 0;
    const shortInfo = door.shortDesc ? `<p class="short-desc">${door.shortDesc}</p>` : '';
    const statusText = locked ? 'locked' : (isSolved(door.day) ? 'gelöst' : 'bereit');

    card.innerHTML = `
      <div class="door-number">#${door.day.toString().padStart(2, '0')}</div>
      <h3>${door.title}</h3>
      <p>${door.topic}</p>
      ${shortInfo}
      <div class="status">${statusText}</div>
    `;

    if (!locked) {
      card.addEventListener('click', () => openDoor(idx));
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') openDoor(idx);
      });
    }
    calendarEl.appendChild(card);
  });
}

function renderLesson(door) {
  const { title, story = [], bullets = [], use, deepDive } = door.lesson;
  const storyHtml = story.map((p) => `<p>${p}</p>`).join('');
  const useHtml = use ? `<p class="use">Einsatz & Warum: ${use}</p>` : '';
  const autoDeep = !deepDive && use && story.length < 5 ? `Vertiefung: ${title} baut auf den vorherigen Schritten auf und zahlt direkt auf ${use} ein.` : deepDive || '';
  const deepHtml = autoDeep ? `<p class="deep">${autoDeep}</p>` : '';
  const bulletsHtml = bullets.length ? `<ul>${bullets.map((b) => `<li>${b}</li>`).join('')}</ul>` : '';

  // Add tools and realWorld info
  const toolsHtml = door.tools ? `
    <div class="tools-section">
      <h5>🛠️ Tools</h5>
      <div class="tools-list">${door.tools.map(t => `<span class="tool-tag">${t}</span>`).join('')}</div>
    </div>
  ` : '';

  const realWorldHtml = door.realWorld ? `
    <div class="real-world-section">
      <h5>🎯 Real-World</h5>
      <p>${door.realWorld}</p>
    </div>
  ` : '';

  lessonEl.innerHTML = `<h4>${title}</h4>${storyHtml}${deepHtml}${useHtml}${bulletsHtml}${toolsHtml}${realWorldHtml}`;
}

function renderGame(door) {
  gameEl.innerHTML = '';
  const title = document.createElement('h4');
  title.textContent = 'Mini-Game';
  const prompt = document.createElement('p');
  prompt.className = 'prompt';
  prompt.textContent = door.game.prompt || door.game.question;
  gameEl.appendChild(title);
  gameEl.appendChild(prompt);

  const type = door.game.type;
  const renderer = gameRenderers[type];
  if (renderer) renderer(door);
}

const gameRenderers = {
  quiz: (door) => {
    const list = document.createElement('div');
    list.className = 'choices';
    door.game.choices.forEach((choice) => {
      const btn = document.createElement('div');
      btn.className = 'choice';
      btn.textContent = choice;
      btn.addEventListener('click', () => {
        if (isSolved(door.day)) return;
        const correct = choice === door.game.answer;
        btn.classList.add(correct ? 'correct' : 'wrong');
        if (correct) {
          markSolved(door.day);
          feedback('Richtig!');
          freezeChoices(list);
        } else {
          feedback('Nope – denk an Kontext.');
        }
      });
      list.appendChild(btn);
    });
    gameEl.appendChild(list);
    if (isSolved(door.day)) freezeChoices(list);
  },

  assemble: (door) => {
    const answerLine = document.createElement('div');
    answerLine.className = 'answer-line';
    const tokenBar = document.createElement('div');
    tokenBar.className = 'token-bar';
    const resetBtn = document.createElement('button');
    resetBtn.textContent = 'Reset';

    const usedMap = new Map();

    const addToken = (value, origin) => {
      const chip = document.createElement('span');
      chip.className = 'token';
      chip.textContent = value;
      chip.dataset.value = value;
      chip.addEventListener('click', () => {
        chip.remove();
        if (origin) origin.classList.remove('used');
      });
      answerLine.appendChild(chip);
      if (origin) origin.classList.add('used');
    };

    door.game.tokens.forEach((tokenValue) => {
      const token = document.createElement('span');
      token.className = 'token';
      token.textContent = tokenValue;
      token.dataset.value = tokenValue;
      token.addEventListener('click', () => {
        if (token.classList.contains('used') || isSolved(door.day)) return;
        addToken(tokenValue, token);
      });
      tokenBar.appendChild(token);
    });

    resetBtn.addEventListener('click', () => {
      answerLine.innerHTML = '';
      tokenBar.querySelectorAll('.token.used').forEach((t) => t.classList.remove('used'));
    });

    const checkBtn = document.createElement('button');
    checkBtn.textContent = 'Check';
    checkBtn.addEventListener('click', () => {
      if (isSolved(door.day)) return;
      const built = [...answerLine.children].map((c) => c.dataset.value);
      const expected = door.game.solution;
      if (expected.length === built.length && expected.every((v, i) => v === built[i])) {
        markSolved(door.day);
        feedback('Korrekt zusammengesteckt.');
      } else {
        feedback('Noch nicht ganz. Hint: ' + (door.game.hint || 'Reihenfolge prüfen.'));
      }
    });

    gameEl.appendChild(answerLine);
    gameEl.appendChild(tokenBar);
    const controls = document.createElement('div');
    controls.className = 'token-bar';
    controls.appendChild(checkBtn);
    controls.appendChild(resetBtn);
    gameEl.appendChild(controls);

    if (isSolved(door.day)) {
      door.game.solution.forEach((val) => addToken(val));
      tokenBar.querySelectorAll('.token').forEach((t) => t.classList.add('used'));
    }
  },

  decode: (door) => {
    const method = document.createElement('div');
    method.className = 'feedback';
    method.textContent = `Methode: ${door.game.method}`;
    const code = document.createElement('div');
    code.className = 'token';
    code.textContent = door.game.encoded;
    const input = document.createElement('input');
    input.placeholder = 'Dekodiertes Ergebnis';
    const btn = document.createElement('button');
    btn.textContent = 'Check';

    btn.addEventListener('click', () => {
      if (isSolved(door.day)) return;
      if (input.value.trim() === door.game.answer) {
        markSolved(door.day);
        feedback('Sauber dekodiert.');
      } else {
        feedback('Nope. Tipp: ' + (door.game.hint || 'prüfe Encoding'));
      }
    });

    gameEl.appendChild(method);
    gameEl.appendChild(code);
    gameEl.appendChild(input);
    gameEl.appendChild(btn);

    if (isSolved(door.day)) input.value = door.game.answer;
  },

  logHunt: (door) => {
    const list = document.createElement('div');
    list.className = 'log-list';
    door.game.logs.forEach((log, idx) => {
      const row = document.createElement('div');
      row.className = 'log-item';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.dataset.flag = log.flag ? '1' : '0';
      cb.id = `log-${door.day}-${idx}`;
      const text = document.createElement('label');
      text.htmlFor = cb.id;
      text.textContent = log.text;
      row.appendChild(cb);
      row.appendChild(text);
      list.appendChild(row);
    });

    const btn = document.createElement('button');
    btn.textContent = 'Check';
    btn.addEventListener('click', () => {
      if (isSolved(door.day)) return;
      const checkboxes = [...list.querySelectorAll('input[type="checkbox"]')];
      const correct = checkboxes.every((cb) => {
        const flagged = cb.dataset.flag === '1';
        return cb.checked === flagged;
      });
      if (correct) {
        markSolved(door.day);
        feedback(door.game.success || 'Richtig markiert.');
      } else {
        feedback('Nicht alle Treffer erwischt.');
      }
    });

    gameEl.appendChild(list);
    gameEl.appendChild(btn);
    if (isSolved(door.day)) {
      list.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
        cb.checked = cb.dataset.flag === '1';
      });
    }
  },

  typing: (door) => {
    const input = document.createElement('textarea');
    input.rows = 3;
    input.placeholder = 'Gib den Payload/Befehl exakt ein';
    const btn = document.createElement('button');
    btn.textContent = 'Check';
    const hint = document.createElement('div');
    hint.className = 'feedback';
    hint.textContent = 'Hinweis: ' + (door.game.hint || 'genau tippen');

    btn.addEventListener('click', () => {
      if (isSolved(door.day)) return;
      if (input.value.trim() === door.game.phrase) {
        markSolved(door.day);
        feedback('Perfekt getroffen.');
      } else {
        feedback('Nicht exakt. Groß/Kleinschreibung & Zeichen prüfen.');
      }
    });

    gameEl.appendChild(input);
    gameEl.appendChild(btn);
    gameEl.appendChild(hint);

    if (isSolved(door.day)) input.value = door.game.phrase;
  },

  portMatch: (door) => {
    const list = document.createElement('div');
    list.className = 'log-list';
    door.game.pairs.forEach((pair, idx) => {
      const row = document.createElement('div');
      row.className = 'log-item';
      const label = document.createElement('span');
      label.textContent = pair.service;
      const select = document.createElement('select');
      select.dataset.answer = pair.answer;
      pair.options.forEach((opt) => {
        const option = document.createElement('option');
        option.value = opt;
        option.textContent = opt;
        select.appendChild(option);
      });
      row.appendChild(label);
      row.appendChild(select);
      list.appendChild(row);
      if (isSolved(door.day)) select.value = pair.answer;
    });

    const btn = document.createElement('button');
    btn.textContent = 'Check';
    btn.addEventListener('click', () => {
      if (isSolved(door.day)) return;
      const selects = [...list.querySelectorAll('select')];
      const correct = selects.every((s) => s.value === s.dataset.answer);
      if (correct) {
        markSolved(door.day);
        feedback('Alles richtig zugeordnet.');
      } else {
        feedback('Mindestens ein Mapping ist falsch.');
      }
    });

    gameEl.appendChild(list);
    gameEl.appendChild(btn);
  }
};

function feedback(text) {
  const existing = gameEl.querySelector('.feedback-msg');
  if (existing) existing.remove();
  const msg = document.createElement('div');
  msg.className = 'feedback feedback-msg';
  msg.textContent = text;
  gameEl.appendChild(msg);
}

function freezeChoices(list) {
  list.querySelectorAll('.choice').forEach((c) => {
    c.classList.add('used');
    c.style.pointerEvents = 'none';
  });
}

function openDoor(index) {
  const door = doors[index];
  if (isLocked(door.day)) {
    logLine(`Zugriff verweigert: Tor ${door.day} ist noch verschlossen.`);
    return;
  }
  currentDoorIndex = index;
  modalDay.textContent = `Tag ${door.day}`;
  modalTitle.textContent = door.title;
  modalTopic.textContent = door.topic;
  renderLesson(door);
  renderGame(door);
  modal.classList.add('open');
  logLine(`Tor ${door.day} geöffnet.`);
}

function closeModal() {
  modal.classList.remove('open');
}

closeModalBtn.addEventListener('click', closeModal);
modal.addEventListener('click', (e) => {
  if (e.target === modal) closeModal();
});

document.addEventListener('keydown', (e) => {
  if (!modal.classList.contains('open')) return;
  if (e.key === 'Escape') closeModal();
  if (e.key === 'ArrowRight') openDoor((currentDoorIndex + 1) % doors.length);
  if (e.key === 'ArrowLeft') openDoor((currentDoorIndex - 1 + doors.length) % doors.length);
});


function boot() {
  logLine('booting adventd...');
  logLine('scan: 26 targets identified (inkl. Bonus-KI-Tore)');
  logLine('ready: öffne ein Tor');
  renderCalendar();
  updateProgress();
}

boot();
