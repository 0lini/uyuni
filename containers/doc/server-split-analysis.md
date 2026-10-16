# Server container split: coupling analysis (Phase 0)

This document looks at what stops the Uyuni server from running on Kubernetes
without systemd as PID 1. For each service it lists the shared state, how other
services reach it, and whether it can leave the all-in-one `server` pod.

It describes the code as of upstream `master` at `16bf4c93`. Every statement
names the file it comes from. Anything this checkout cannot answer is listed
under [Open questions](#open-questions) and is not assumed.

## How the server starts today

1. The chart's `init-volumes` init container copies image content into
   empty PVCs (`containers/server-helm/templates/server.yaml`). The
   `db-waiter` init container then waits for both databases.
2. `/docker-entrypoint-init` runs `docker-entrypoint-init.d/*.sh` in order:
   - `00-mgrSetup.sh`, first install only: sets up the DB and report DB, runs
     `spacewalk-setup`, then starts Tomcat and Apache **by hand, without
     systemd** to create the first admin user, and stops them again.
   - Small edits to `rhn.conf`, postfix, the time zone and Java debug options.
   - `91-schema-update.sh` runs `spacewalk-startup-helper check-database`,
     which also runs as the `uyuni-check-database.service` unit.
   - `99-cgroupfs-mount.sh` mounts cgroup2. This is the reason the pod needs
     `SYS_ADMIN`.
3. `exec /usr/lib/systemd/systemd` then starts `spacewalk.target`
   (`spacewalk/admin/spacewalk.target`) and the services enabled in the image
   (`sssd`, `prometheus-node_exporter`, `timezone_alignment`). The
   `etc-systemd-multi` and `etc-systemd-sockets` PVCs keep the set of enabled
   units across restarts.

Oneshot units that `spacewalk.target` pulls in:

| Unit | What it does | Ordering |
|---|---|---|
| `uyuni-update-config` | runs `uyuni-configfiles-sync sync`, FIPS crypto policy, SCC UUID, GPG keyring import, copies the CA into the Salt tree, moves settings from `rhn.conf` into the DB, hostname rename | before check-database, cobblerd, tomcat, apache2, rhn-search, taskomatic, postfix |
| `uyuni-check-database` | DB version check plus schema upgrade | before every service; `Requires=ca-certificates.service` |
| `salt-secrets-config` | writes `/etc/salt/master.d/{susemanager_engine,susemanager_db,uyuni_roster}.conf` and `susemanager-users.txt` from `rhn.conf`; creates the salt-api TLS cert and adds it to the trust store | before salt-master |
| `spacewalk-wait-for-tomcat` | `lsof` until the Tomcat **PID** listens on 8005 and 8009 | after tomcat, before apache2 |
| `spacewalk-wait-for-salt` | no-op ordering | after salt-master and salt-api, before httpd |
| `spacewalk-wait-for-taskomatic` | `lsof` until something listens on 2829 | after taskomatic |
| `cobbler-refresh-mkloaders` | `cobbler mkloaders` | after cobblerd and taskomatic |

Probes: `liveness-check.sh` calls `systemctl is-active multi-user.target`.
`healthcheck.sh` (the podman `HEALTHCHECK`) also uses it.
`rhn-sat-restart-silent` already skips systemd inside a container: it writes
`/var/run/uyuni-restart-pending`, the liveness probe fails, and kubelet
restarts the container. That mechanism keeps working without systemd.

## Per-service findings

"Reached by" lists the callers and the endpoint they use. **Hardcoded** means
the endpoint cannot be changed through configuration today.

### rhn-search

- **State:** its index in `/var/lib/rhn/search` (dedicated `var-search` PVC,
  `search.index_work_dir`); reads `/etc/rhn/rhn.conf` for DB credentials
  (`search-server/.../config/Configuration.java`); logs to
  `/var/log/rhn/search`.
- **Reached by:** Tomcat and Taskomatic over XML-RPC
  `http://<search_server.host>:<search_server.port>/RPC2`, default
  `localhost:2828` (`ConfigDefaults.java:723-731`). The listen address is a
  **separate** key, `search.rpc_address`, default `127.0.0.1`
  (`RpcServer.java:69-73`).
- **Needs changing:** set `search.rpc_address=0.0.0.0` in the search
  container and `search_server.host=search` on the clients. Both are config
  keys, so no code change is needed. The chart already has a `search` Service
  (port 8002, debug only), which would gain port 2828.
- **Placement:** can be a **separate Deployment**. Its only PVC
  (`var-search`) is used by nothing else. It needs `rhn.conf`, or at least
  the `db_*` keys, from a Secret or a read-only copy.

### Taskomatic

- **State:** writes repo metadata to `/var/cache/rhn/repodata`, which Apache
  serves through X-Sendfile. Runs `spacewalk-repo-sync`, which writes
  `/var/spacewalk/packages`. Writes Salt files under `/srv/susemanager/salt`,
  `/srv/susemanager/pillar_data` and `/srv/susemanager/tmp`
  (`SaltConstants.java`). Writes Cobbler templates in
  `/var/lib/cobbler/templates` and snippets. Uses GPG keys in
  `/var/spacewalk/gpg` and `/var/lib/spacewalk/gpgdir` through
  `mgr-sign-metadata`. Runs `subscription-matcher`, `virtual-host-gatherer`
  and other local binaries (`grep SystemCommandExecutor`).
- **Reached by:** Tomcat over XML-RPC `tasko_server.host:2829`. Python
  `spacewalk/server/taskomatic.py` has **hardcoded**
  `http://localhost:2829/RPC2`; it is used by `reposync.py`,
  `packageImport.py` and `mgr_sync.py`. Apache proxies `/tasko-exporter`
  (9800) and `/tasko-jmx` (5557) on `localhost`.
- **Blocker for a separate pod:** `TaskoXmlRpcServer.java:52` **binds** to
  `tasko_server.host`, the same key clients use to connect. Setting it to a
  Service name would make Taskomatic try to bind to the ClusterIP and fail.
  A separate bind key is needed first, plus a configurable URL in
  `taskomatic.py`.
- **Placement:** **must share a pod with Tomcat, Apache and Salt** unless the
  volumes above become RWX. It can be its own container in that pod, because
  `localhost` keeps working across containers in one pod.

### Tomcat

- **State:** everything Taskomatic touches (both run the same Java code
  base), plus `/var/lib/salt/.ssh` (salt-ssh keys and known_hosts),
  `/var/cache/salt/master/minions/` (files minions push with `cp.push`,
  read back by Java), `/srv/formula_metadata`, `/srv/www/os-images`, and
  `/etc/pki/trust/anchors` (CA upload; `CertificateUtils.java` falls back to
  `update-ca-cert-trust.sh` when `ca-certificates.path` is missing, so it
  already works without systemd).
- **Reached by:** Apache over AJP on hardcoded `localhost:8009` and
  WebSocket `localhost:8080` (`zz-spacewalk-www.conf`). Cobbler calls back
  through `uyuni_authentication_endpoint: http://localhost`, which
  `95-post-upgrade.sh` resets on every start.
- **Runs privileged helpers through sudo** (`spacewalk/config/etc/sudoers.d/spacewalk`):
  `rhn-sat-restart-silent`, `rhn-config-satellite.pl`, `rhn-bootstrap`,
  `rhn-ssl-tool`, `mgr-monitoring-ctl`, `service taskomatic restart`. In a
  split, these must stay in the same container as Tomcat or be replaced.
- **Placement:** the anchor of the pod. Phase 3 only.

### Apache (apache2)

The plan lists Apache as a low-coupling candidate based on
`proxy-httpd-image`. **The code says otherwise:**

- It serves files directly from disk via `XSendFile` on
  `/var/spacewalk/packages`, `/var/spacewalk/rhn/{comps,modules}` and
  `/var/cache/rhn/repodata`. Tomcat only returns the header.
- It runs the **Python backend in-process** through mod_wsgi: `/XMLRPC`,
  `/APP`, `/PACKAGE-PUSH` (`python/spacewalk/apache-conf/zz-spacewalk-server-wsgi.conf`),
  using `/etc/rhn/rhn.conf`, the DB and `/var/spacewalk`.
- It serves `/srv/www/htdocs` (pub, bootstrap, CA cert), `/srv/www/os-images`
  and `/srv/tftpboot` (the existing `tftp` Deployment fetches files through
  `http://web`). Cobbler output under `/srv/www` is probably also served
  here; see open questions.
- It proxies `/cobbler_api` to cobblerd and restricts it to `127.0.0.1`
  (`01-cobblerapi.conf`). Java reaches Cobbler through this proxy
  (`CobblerConnection.java`, `cobbler.host`, default `localhost`).
- It reaches Tomcat, the exporters and Taskomatic over `localhost`.
  Saline (`http://saline:8216`) and the Hub API (`uyuni-hub-xmlrpc-0:2830`)
  already go through Service names.
- **Placement:** a **sidecar container in the server pod**. A separate
  Deployment would need RWX for `srv-www`, `var-spacewalk` and `var-cache`,
  plus a copy of the Python backend and `rhn.conf`. That is not a
  low-coupling first step.

### salt-master and salt-api

- **State:** `/etc/salt` (pki, generated `master.d/*.conf`),
  `/run/salt/master` (IPC sockets, on the `run-salt-master` PVC),
  `/var/cache/salt` (job cache, `cp.push` uploads), `/var/lib/salt/.ssh`,
  `/srv/salt`, `/srv/pillar`, `/srv/susemanager/*` (written by Java),
  `/usr/share/susemanager/{salt,modules,reactor}` from the image
  (`spacewalk/setup/salt/susemanager.conf`).
- **Reached by:** minions on 4505/4506 (the `salt` Service). Java calls
  salt-api at `java.salt_api_host:9080`, default `localhost`
  (`SaltService.java:139`); salt-api binds `127.0.0.1` (`rest_cherrypy.host`).
  Events go **through the DB**, not a socket: the `mgr_events` engine writes
  to PostgreSQL. `ext_pillar` (`suma_minion`) and `master_tops` read the DB.
  Saline reads `/run/salt/master` and `/etc/salt` from the same PVCs.
- **Configuration depends on `rhn.conf`:** `salt-secrets-config.py` has to
  run before the master starts. That works as an init container.
- **Placement:** salt-master and salt-api must share a container or pod
  (IPC in `sock_dir`). Both must share a pod with Tomcat and Taskomatic
  because of the shared file trees and the RWO PVCs.

### cobblerd

- **State:** `/var/lib/cobbler` (`var-cobbler` PVC; Java writes templates and
  snippets here), `/etc/cobbler`, `/srv/tftpboot`, `/srv/www` (via Apache).
  `cobbler mkloaders` needs the grub2 and syslinux packages from the image.
- **Reached by:** Java over `http://localhost/cobbler_api` through Apache,
  and cobbler authenticates back through `http://localhost` → Tomcat. A
  `cobbler` Service on 25151 already exists and selects the server pod.
- **Placement:** a sidecar in the server pod, Phase 2.

### postfix

- **State:** `/etc/postfix` (PVC); `10-setup-mail.sh` sets `myhostname`;
  `config_postfix` runs `config.postfix` on first start.
- **Reached by:** Java via `java.smtp_server` (default `localhost`,
  configurable). Python `rhnMail.py:80` has **hardcoded**
  `smtplib.SMTP("localhost")`.
- **Placement:** an **optional sidecar** works unchanged, because
  `localhost` stays valid. A separate Deployment, or dropping postfix in
  favour of an external relay, needs `rhnMail.py` to read a host setting
  first.

### sssd

- **State:** `/etc/sssd` (PVC). Tomcat authenticates through PAM
  (`pam_auth_service = susemanager`, `root/etc/pam.d/susemanager*`). The PAM
  and NSS modules inside the Tomcat process talk to sssd over Unix sockets.
- **Placement:** an **optional sidecar** that shares the sssd pipes
  directory with the Tomcat container via an emptyDir. It cannot be a
  separate Deployment. See open questions for the socket path.

### Exporters

- **JMX exporters (5556 Tomcat, 5557 Taskomatic):** Java agents **inside**
  the Tomcat and Taskomatic JVMs, enabled by `mgr-monitoring-ctl` →
  `salt-call --local state.apply srvmonitoring.enable`, which edits
  `/etc/tomcat/conf.d` and `/etc/rhn/taskomatic.conf`. They cannot be split
  out. The Taskomatic metrics endpoint (9800) also runs in-process.
- **node_exporter (9100):** a separate process, enabled at image build time.
  Inside a pod it reports the container's view of the node. On Kubernetes
  the cluster's own node exporter normally covers this, so **dropping it on
  Kubernetes** is a better option than a sidecar. The chart already exposes
  it through the `tomcat-internal` Service and the ingress.
- **postgres_exporter (9187):** a separate process configured by the
  `srvmonitoring` state (it writes `60-server.conf`, `pg_passwd`). It only
  needs DB access, so it can be a separate Deployment or move next to the
  `db` Deployment.
- **Monitoring toggle:** the `srvmonitoring` state uses `service.running`
  and `systemctl_reload`, so it will break without systemd. Under Kubernetes
  it needs replacing with chart values (`enableMonitoring` exists already).

## Assumptions in `uyuni-configfiles-sync`, `00-mgrSetup.sh`, `spacewalk-service`

- **`uyuni-configfiles-sync`:** `init` runs at image build time and
  records, in `/etc/uyuni-configfiles-sync/`, the packaged files for 10 PVC
  paths (`Dockerfile.uyuni`/`Dockerfile.mlm` lines 116-125). `sync` runs
  from `uyuni-update-config` and so needs systemd. It rsyncs package
  defaults into the PVCs, makes `.rpmnew` or `.rpmsave` files, and then
  **runs the `%pre/%post/%preun/%postun/%posttrans` scriptlets of every
  owning package**. Those scriptlets assume the full package set is
  installed in the **same filesystem** and may call `systemctl` (masked with
  `DISABLE_RESTART_ON_UPDATE=1`). A per-service image would need to run it
  only for its own PVCs and packages. The single `.buildhash` lock in
  `/etc/sysconfig` (itself a PVC) assumes **one image version per pod**:
  two containers built from different images would keep overwriting each
  other's lock and re-running the sync.
- **`00-mgrSetup.sh`:** assumes DB clients, `spacewalk-setup`, Tomcat and
  Apache are all in the same filesystem, and creates the first user through
  `curl http://localhost/rhn/...`. It already starts Tomcat and Apache
  without systemd. It writes `/etc/rhn/rhn.conf` and the marker file
  `/var/spacewalk/.MANAGER_SETUP_COMPLETE` that later starts depend on. This
  maps well to a one-shot init container that uses the server image.
- **`spacewalk-service`:** builds its service list from `spacewalk.target`
  and drives everything through `systemctl`, `lsof` against systemd's
  MainPID, and `pgrep httpd`. It is the chart's `preStop` hook and is what
  admins run inside the container. Without systemd it either needs a non-
  systemd backend or must be retired on Kubernetes (pod restart replaces
  `restart`). This also affects mgradm, which calls it for podman
  installs.

## Pod-vs-Deployment summary

All PVCs the chart creates are `ReadWriteOnce` (`templates/pvcs.yaml`). RWO restricts a
volume to one **node**, not one pod. Two pods can share a RWO PVC only when
they land on the same node.

**This already affects the shipped chart:** the `saline` Deployment mounts
`run-salt-master` and `etc-salt`, which the server pod also mounts, and it
has no pod affinity to the server pod (`templates/saline.yaml`,
`uyuni.nodePlacement`). On a multi-node cluster with block storage it can
get stuck on a multi-attach error. Any new Deployment that shares a server
PVC needs `podAffinity` to the server pod, or the volume must be `RWX` or
`ReadWriteOncePod`, with the sidecar pattern instead.

| Service | Separate Deployment | Sidecar in server pod | Blockers |
|---|---|---|---|
| rhn-search | **yes** | yes | `rhn.conf` delivery; port 2828 on the `search` Service |
| postgres_exporter | **yes** | yes | DB credentials; replace the `srvmonitoring` systemd state |
| node_exporter | drop on k8s | yes | none |
| postfix | only after a `rhnMail.py` change | **yes** | `localhost` hardcoded in Python |
| sssd | no | **yes** | shared socket directory with Tomcat |
| Apache + mod_wsgi backend | no (RWX needed) | **yes** | X-Sendfile, mod_wsgi, `/cobbler_api` `127.0.0.1` ACL |
| cobblerd | no (RWX needed) | **yes** | shared `/var/lib/cobbler`, `/srv/tftpboot` |
| salt-master + salt-api | no (RWX needed) | **yes**, as one container | shared Salt trees; `salt-secrets-config` as init container |
| Taskomatic | no (RWX needed) | **yes** | bind and client share one key; hardcoded URL in Python |
| Tomcat | n/a | pod anchor | sudo helpers, setup |
| JMX / Taskomatic metrics | n/a | in-process | none |

## Recommended order

1. **Probes and entrypoint groundwork, no split:** make
   `liveness-check.sh` stop depending on `systemctl` (use per-service
   checks) so later phases can use it unchanged. Fix the missing
   `podAffinity` on `saline`.
2. **rhn-search as its own Deployment** behind a chart value. It is the only
   service with its own PVC and only config-key changes. It is a good
   template for the image, chart, schema and test pattern.
3. **postgres_exporter** next to the DB, and **node_exporter** disabled on
   Kubernetes. A Kubernetes alternative to the `srvmonitoring`
   enable/disable flow is needed here.
4. **postfix and sssd as optional sidecars**. They don't need code changes
   because `localhost` still works inside the pod.
5. **Code prerequisites, one small PR each:** a separate Taskomatic bind
   key; a configurable Taskomatic URL in `taskomatic.py`; a configurable SMTP
   host in `rhnMail.py`.
6. **Salt (master and API) as a sidecar**, with `salt-secrets-config` as an
   init container. Then **cobblerd** and **Taskomatic** as sidecars.
   Readiness probes and init containers replace the
   `spacewalk-wait-for-*` units.
7. **Apache + Tomcat and the entrypoint** (Phase 3): turn `00-mgrSetup.sh`,
   schema upgrade and `uyuni-configfiles-sync` into init containers; drop
   `99-cgroupfs-mount.sh`, `99-kubernetes.conf`, the unit masking and
   `SYS_ADMIN`.

Compared to the plan, this moves **Apache from Phase 1 to Phase 3** and adds
the code prerequisites in step 5.

## Open questions

These cannot be answered from this repository alone:

1. **Cobbler's Apache config** (`/etc/apache2/conf.d/cobbler.conf`, from the
   cobbler package) is not in this repo. Which paths does it proxy or serve
   (`/cobbler_api` → `127.0.0.1:25151`, `/cblr`, `/cobbler`)? This decides
   whether cobblerd can ever leave the Apache pod.
2. **Who uses the `cobbler` Service on port 25151** (`templates/services.yaml`)?
   Nothing in `proxy/` or `java/` connects to it directly. Possibly the proxy
   or an external caller.
3. **mgradm (uyuni-tools)** was not inspected; it is outside this session's
   repository scope. What does it run inside the container
   (`spacewalk-service`, `systemctl`, `journalctl`, `mgr-*` helpers), and
   does it rely on `healthcheck.sh` or the `etc-systemd-*` volumes? That
   decides how a podman install runs a split layout. The likely answer is a
   podman "pod" with the same containers, or the all-in-one image staying
   the default for podman.
4. **sssd socket path** in the SLE packages (`/var/lib/sss/pipes` by
   default): is it relocatable to a shared emptyDir without patching sssd?
   Do `nsswitch.conf` lookups in Tomcat need sssd at startup?
5. **RPM scriptlets replayed by `uyuni-configfiles-sync`:** which of them
   still call `systemctl` or `%service_*` macros, and what happens when they
   do with no systemd running? It needs a per-package audit before
   `uyuni-update-config` can run as an init container.
6. **`ca-certificates.path`:** salt-secrets-config and `CertificateUtils`
   fall back to running the update script. Are there other writers to
   `/etc/pki/trust/anchors` that rely on the path unit, for example
   `mgr-ssl-cert-setup`?
7. **Storage class in the target environments:** if RWX (for example
   Longhorn RWX or NFS) is acceptable, more services could become separate
   Deployments. The recommendation above assumes RWO only.
8. **Port 8080 for the `/rhn/websocket` proxy:** confirm which Tomcat
   connector serves it, so the Tomcat readiness probe checks the right port.
