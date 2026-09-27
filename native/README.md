# Transitional Docker-free Mailcow runtime — staged source only

Source baseline `02552ffefdf0869f988edf4a7e03822e8b467b34`; all 18 currently
running service images are pinned by **repository manifest digest** in
`pinned-images.json`. Image config IDs are not interchangeable with pullable
manifest digests. No production configuration, environment, mail data,
certificates, keys or customer identities are copied here.

This first port uses isolated native processes under systemd with the exact
upstream-packaged root trees. It preserves Alpine musl and Debian glibc/module
ABI instead of upgrading Dovecot or rebuilding an entire groupware stack as a
side effect of removing Docker. This is a transitional runtime, not distro
modernization. Upstream OCI images remain an off-host build/patch source; Docker
and containerd are absent from the target runtime after parity acceptance.

## Concrete current map

`runtime-manifest.json` maps all 18 source services, 14 Ofelia jobs, 12 named
state volumes, every bind target, port/environment template, dependency and
network/capability requirement. Generate it with `build_manifest.py` + PyYAML
using only the committed Compose source and pin file; no live secrets input.
Declared image sizes sum to 4,616,410,431 bytes before deduplication/compression.
That is **not** the new-runtime peak disk/RAM estimate. Staging a second unpacked
copy on the constrained VPS is prohibited until the operator recovers capacity
and verifies the complete peak, including state rehearsal and rollback.

Verified binaries: Postfix 3.10.12, Dovecot 2.3.21.1 + Pigeonhole/Lua/SQL/LDAP/
FTS-flatcurve, Rspamd 4.1.4, ClamAV 1.4.6, SOGo source build 5.12.10 + SOPE,
MariaDB 10.11.19, Redis 7.4.10, PHP 8.2.29, nginx 1.30.4, Unbound 1.25.1,
memcached 1.6.45. SOGo has no installed `sogo` Debian package; copying only a
package list would lose the compiled groupware application. Olefy installs
oletools from floating master upstream; the deployed image digest seals the
current artifact, but subsequent maintenance must pin a source commit.

## Smallest maintainable packaging/lifecycle path

1. Off-host Linux x86_64 builder fetches the 18 pinned OCI manifests/layers and
   verifies digests. `skopeo copy` + rootful `umoci unpack` preserve numeric UID,
   modes, hardlinks and ABI. Do not extract live Docker roots or volume data.
   Emit per-service root-tree tar/checksum, image source identity, SBOM and
   library/module version assertions. Build an aggregate artifact index.
2. Deduplicate **immutable byte-identical library files only** with identical
   metadata by hardlinks where the filesystem supports it. Never merge different
   libc/module versions or deduplicate writable data/configuration. This can
   share page cache as well as disk; measured PSS remains required. A compressed
   RootImage can lower staging bytes but needs complete systemd mount support
   and does not guarantee cross-image shared-page savings.
3. Stage root-owned read-only release roots under `/opt/mailcow-native/releases`;
   mutable templates/configs go into a separate root-owned release configuration
   area. Bind existing/rehearsal volumes at their exact legacy paths with the
   same numeric IDs, including vmail 5000, Dovecot 401/402, SOGo 999, Postfix
   101/102/103. Keep SQL/store/index/queue/cert paths separately explicit.
4. Units use `RootDirectory`, appropriate mount namespaces, `PrivateDevices`,
   read-only source, bounded `TasksMax`/CPU/memory accounting and precise writable
   binds. Start with original bootstrap/daemon behavior for parity; split
   supervisors/bootstrap/logging into native unit roles only after comparing
   their complete subprocess/restart behavior. Avoid a new heavy orchestration
   daemon. Preserve ClamAV/freshclam and all scanning features.
5. Use a dedicated persistent mail network namespace and private host link,
   root-owned generated service aliases/address assignments and explicit
   firewall/DNAT routes. Preserve resolver/DNSBL/DNSSEC and SMTP outbound source
   behavior. Do not let old `0.0.0.0` container listeners escape onto the host.
   Default rehearsal has **no public listener, MX route or outbound delivery**.
   Validate every service connection from the manifest and the original
   Postfix/Dovecot/SOGo/Rspamd configs; namespace/DNS changes need tests.
6. Keep a mail-only native nginx target behind the existing host edge proxy,
   so Mailcow UI restart/stop cannot stop Studio or its TLS endpoint. Shared
   certbot owns issuance; atomic hook installs consistent cert/key pairs into
   mail TLS paths then calls only mail reload actions. Preserve trusted-host,
   ActiveSync, DAV/calendar/contact, webmail and admin routes/assets/branding.
7. Preserve Redis persisted state, MC_CHANNEL pubsub and existing log list
   shapes. A Unix socket control adapter authenticates allowed local service
   peers; isolate Mailcow Redis and ACLs from Mem0/FreeFrame. Both HTTP and Redis
   dispatch use the same closed typed operation policy.
8. Map all 14 jobs to systemd timers/oneshots, retaining master-node checks,
   no-overlap, exact user, failures and backup retention. Watchdog must keep
   its checks/alerts/backoff and avoid recursive restart loops; netfilter must
   retain mail-specific ban policies and Redis state. These adapters are still
   required before the source can be activated.

## Implemented first policy boundary

`action_policy.py` compiles every actual `container_post__*` operation in the
pinned/deployed DockerApi source: **29 operations**, plus separate host stats
observation. The deployed method inventory was read from its AST, not guessed
from documentation. This reconciles the earlier “30 operations” count.

The policy binds each exec family to the exact mail service; unit names and
executables are fixed, scalar inputs stay argv entries, queue IDs and ACL rights
are validated, maildir/disk paths are restricted, and controller secrets never
appear in printable plans. HTTP and MC_CHANNEL share the compiler. Six tests
verify complete operation coverage and command/service/path injection denials.

The compiler is a reviewable boundary, **not an activated executor**. Remaining
primitives include atomic maildir/index moves, MariaDB socket maintenance,
Rspamd secret hashing/atomic install, ACL enumeration/response formatting,
service stats compatibility, local peer authentication and API transport glue.
No placeholders are advertised as functioning mail features.

## Data and recovery gate

Rehearsal restores an off-host, verified consistent MariaDB backup + all named
volumes/bind state into isolated addresses. Preserve Maildir message files,
UIDVALIDITY/UIDNEXT/indexes, flags/folders, user hashes/quota/Sieve/ACLs,
SOGo calendar/contact/ActiveSync state, Redis policy/bans/logs, Postfix queues,
TLS/DKIM material and spam/AV state. Inventory bootstrap writes before running
old entrypoints on any rehearsal copy. Do not symlink production writable data
into concurrent old/new writers.

Cutover requires a short coordinated receive/submission/admin/groupware write
pause, queue drain or exact durable queue transfer, fresh incremental mail and
SQL/state sync, exclusive writer ownership and count/flag/hash validation.
After new mail/calendar/admin writes, rollback must sync those writes and queue
state back before restoring old listeners; a stale-store rollback is forbidden.
Keep immutable old images, their state and verified backup retrieval until this
procedure has a successful rehearsal. Both explicitly authorized inbound and
outbound delivery and the complete P5 parity checklist remain required.

Packaging references:
[Skopeo copy and digest preservation](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-copy.1.md),
[umoci unpack](https://umoci.cyphar.com/quick-start/),
[systemd execution roots and isolation](https://www.freedesktop.org/software/systemd/man/systemd.exec.html).
