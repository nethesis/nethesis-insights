# Review rules (draft 5)

Labels: customer = send to the customer; internal = keep for Nethesis;
dismiss = nobody needs to act. Rules are checked in order; the first that
matches wins. When none matches: dismiss.

## General rules (checked first)

G1. Security findings go to the customer: attacks, login attempts, probes
    and scans, blocked or not, and successful root SSH logins (C7).
    Exception: Dovecot master-user logins (D5) are dismissed.
G2. Development problems the customer cannot act on are internal: bugs in
    our code, problems in the configuration we ship, our own plumbing and
    infrastructure (I1-I5).
G3. Configuration errors the administrator can fix go to the customer
    (C4, C6).
G4. Temporary faults are never sent to the customer: timeouts, dropped or
    refused connections, a service that failed while stopping and will
    probably be restarted. Dismiss them, unless I4 makes them internal.

## Send to the customer

C1. The machine itself is in trouble: a crash with a core dump (any process,
    internal helpers such as BusyBox included), the core-dump handler itself
    timing out, a kernel soft lockup or hung task, out of memory.
C2. A feature the customer configured or relies on stopped: host or module
    updates failed, subscription check failed, PhoneHome failed, a backup or
    a scheduled job of a customer feature failed to start (backup timers, CDR
    cleanup, calendar sync, phonebook sync).
C3. Someone is trying to log in or probing: SSH probing or brute force
    (including malformed SSH handshakes), SMTP AUTH failures, SIP
    authentication failures, repeated failed logins to NethVoice, Nextcloud
    or the NethSecurity controller, web scanners asking for paths that do
    not exist, non-SMTP traffic on the mail port, SIP scanners (including
    those already blocked by the proxy).
C4. Configuration the administrator must fix: FreePBX notifications
    XTNCONFLICT (conflicting extensions), BADDEST (bad destinations), fax
    users without email; any setting, user or association that points to a
    user, extension, queue or profile that does not exist.
C5. A user's mail data or mail rules are broken: corrupted mailbox cache,
    a user's own Sieve script failing, Dovecot out of memory.
C6. A setting the administrator left empty that disables a feature (e.g. the
    MaxMind licence on the controller).
C7. Successful root SSH logins.

## Keep internal

I1. A bug in our code: ReferenceError, TypeError, panic, unhandled
    exception, parser error, PHP warning, in NethVoice/NethCTI, the
    middleware, Webtop, FreePBX/Tancredi glue or Mattermost.
I2. Our infrastructure: the rclone backup gateway, the cluster task queue
    (Redis), monitoring/Prometheus/alert delivery, Loki queries made by our
    collector.
I3. The NethVoice proxy failing in itself: kamailio or rtpengine not
    starting, the media proxy unavailable, Redis unreachable, codec,
    transcoding or SRTP crypto negotiation problems. (Parse, TLS and
    connection errors caused by outside traffic: D10.)
I4. Our own plumbing failing: the satellite database and transcription
    (MQTT, helper missing, deadlock), report and queue-statistic jobs,
    internal connections refused or timing out, broken or disabled FreePBX
    modules, default ARI credentials, sound-file conflicts, a product
    logging personal data or passwords.
I5. Capacity limits in a product we ship: Apache MaxRequestWorkers, PHP-FPM
    pool busy, database "too many connections", database buffer pool too
    small. A request that timed out is not one of these: D13.
I6. Deprecated functions or syntax in the configuration we ship (e.g.
    Traefik rules).

## Dismiss

D1. Third parties' problems: remote senders' SPF/DKIM/DNS, rspamd DNS or
    Redis lookups, client hostnames that do not resolve, malware rejected.
D2. Normal user actions failing: a call hangup, transfer, pickup, parking or
    queue action failing; authorization or capability denied to a user.
D3. Expected setup noise: domain binding warnings, "trust" authentication at
    initdb, Apache ServerName, outdated TimescaleDB, deprecated functions or
    syntax outside our shipped configuration, empty FreePBX profile/operator
    config, HTTP/2 inactive, module signature checking disabled, "not
    running as root" firewall warnings, [DEV] debug lines in the proxy.
D4. Phone provisioning requests for unknown models (patterns.d template not
    found).
D5. Dovecot master-user (impersonated) logins, whether they succeed or
    fail: this is support access, not an attack.
D6. Aborted MariaDB connections, CTI socket resets, listener-leak warnings.
D7. A service that failed while stopping or will be restarted: a single
    generic "X.service: Failed with result 'exit-code'" line, or a process
    killed by systemd at stop.
D8. Dovecot authentication errors "auth: Error: plain(...): user ... found
    from any userdbs".
D9. Steps skipped with "fork/exec ... permission denied" during an action.
D10. NethVoice proxy parse, TLS-handshake and connection errors
    (reset, refused, no route, timeout, branch limit) caused by outside
    traffic or broken phones.
D13. Requests that timed out: backend or upstream timeouts, preview or
    conversion timeouts.
