#!/bin/bash
# Host setup for the forgejo-runner workload.
#
# Usage:
#   setup.sh enable    — mint a fresh registration token, prune the stale runner
#   setup.sh disable   — remove the minted token
#   setup.sh artifacts — print what enable() leaves on the host (read-only)
#
# Idempotent in both directions. Called by workloadctl enable/disable, before the
# cloud-init seed is built, so the token it writes is what the seed reads.
#
# WHY THIS EXISTS: a Forgejo registration token is one-shot — the first
# registration consumes it — so a rebuilt VM cannot replay a stored one. Minting
# fresh on every provision (and feeding it to the seed through the credstore) is
# what makes `disable --purge` + `enable` a working reset. The Forgejo API
# token never leaves the host; the guest receives only the runner's own
# uuid and token.
set -euo pipefail

WORKLOAD_NAME="${WORKLOAD_NAME:?not set — run via workloadctl enable/disable}"
WORKLOAD_INSTANCE_DIR="${WORKLOAD_INSTANCE_DIR:?not set — run via workloadctl enable/disable}"

# Unscoped credstore names. The cloud-init template form ${SECRET?name} admits no
# '/' (see secrets_template.py), so the minted token must be a plain name; the
# admin token is unqualified for the same reason, plus it is read by this script
# rather than by a workload.
ADMIN_CRED=/etc/credstore.encrypted/forgejo-admin-token
UUID_CRED=/etc/credstore.encrypted/forgejo-runner-uuid
TOKEN_CRED=/etc/credstore.encrypted/forgejo-runner-token
# The runner is named after the workload, so a forge shows one row per
# instance and `init --as` renames both together.
RUNNER_NAME="$WORKLOAD_NAME"

forgejo_admin_url() {
  # The instance TOML, not the bundle: `init --as` renames the instance and the
  # operator edits its copy. Same read Sunshine's setup.sh does.
  python3 - "$WORKLOAD_INSTANCE_DIR/workload.toml" <<'PY'
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
tv = d.get("vm", {}).get("cloud_init", {}).get("template_vars", {})
print(tv.get("FORGEJO_ADMIN_URL", ""))
PY
}

runner_scope() {
  # Where the runner is created, as the API path between /api/v1/ and
  # /actions/runners. FORGEJO_RUNNER_SCOPE: empty for the token's own user,
  # NAME for an organisation, OWNER/REPO for one repository. Never the
  # instance (/admin/...): an instance runner takes jobs from every repo on
  # the forge, a stranger's included, and a job there reaches the signing key.
  python3 - "$WORKLOAD_INSTANCE_DIR/workload.toml" <<'PY'
import re, sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
tv = d.get("vm", {}).get("cloud_init", {}).get("template_vars", {})
scope = tv.get("FORGEJO_RUNNER_SCOPE", "")
name = r"[A-Za-z0-9][A-Za-z0-9._-]*"
if scope == "":
    print("user")
elif re.fullmatch(name, scope):
    print("orgs/" + scope)
elif re.fullmatch(name + "/" + name, scope):
    print("repos/" + scope)
else:
    sys.exit("ERROR: FORGEJO_RUNNER_SCOPE %r is not empty, NAME or OWNER/REPO"
             % scope)
PY
}

network_shape() {
  # FORGEJO_URL (empty = same-host forge) and SAME_HOST_HOSTNAMES. Same read as
  # forgejo_admin_url, both values on one line space-separated.
  python3 - "$WORKLOAD_INSTANCE_DIR/workload.toml" <<'PY'
import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
tv = d.get("vm", {}).get("cloud_init", {}).get("template_vars", {})
print(tv.get("FORGEJO_URL", ""), tv.get("SAME_HOST_HOSTNAMES", ""))
PY
}

# Delete any existing runner with our name so re-provisioning does not leave an
# offline row behind per reset. Best-effort: a list/delete failure is a
# housekeeping miss, not a reason to fail the provision.
prune_stale() {
  # The admin token travels via the environment, never argv: argv is visible
  # in `ps` to every user on the host, /proc/<pid>/environ is root-only.
  ADMIN_TOKEN="$ADMIN_TOKEN" python3 - "$RUNNERS_URL" "$RUNNER_NAME" <<'PY' || echo "  (could not prune stale runners)"
import json, os, sys, urllib.request
url, name = sys.argv[1], sys.argv[2]
token = os.environ["ADMIN_TOKEN"]
auth = {"Authorization": "token " + token}

def call(req):
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read()

try:
    runners = json.loads(call(urllib.request.Request(
        url, headers=auth)))
except Exception as e:
    print("  list runners failed: %s" % e)
    raise SystemExit(0)

for run in runners if isinstance(runners, list) else []:
    if run.get("name") == name:
        try:
            call(urllib.request.Request(
                "%s/%s" % (url, run["id"]),
                method="DELETE", headers=auth))
            print("  pruned stale runner id=%s" % run["id"])
        except Exception as e:
            print("  could not prune runner id=%s: %s" % (run["id"], e))
PY
}

case "${1:-}" in
  enable)
    if [ ! -s "$ADMIN_CRED" ]; then
      {
        echo "WARNING: no Forgejo admin API token at $ADMIN_CRED"
        echo "  The VM will provision, but the runner cannot register and will"
        echo "  sit idle. Create a Forgejo token for the runner's scope, then:"
        echo "    workloadctl secret create forgejo-admin-token"
        echo "    workloadctl enable $WORKLOAD_NAME      # re-run to mint"
      } >&2
      exit 0
    fi

    FORGEJO_ADMIN_URL="$(forgejo_admin_url)"
    if [ -z "$FORGEJO_ADMIN_URL" ]; then
      echo "ERROR: [vm.cloud_init.template_vars].FORGEJO_ADMIN_URL is empty in" >&2
      echo "  $WORKLOAD_INSTANCE_DIR/workload.toml — nothing to register against." >&2
      exit 1
    fi

    # Same-host shape: the forge's ROOT_URL host must be mapped in the guest's
    # /etc/hosts, or Forgejo's ROOT_URL-derived action URLs (cache, artifact
    # uploads) are unreachable from the guest. A configured FORGEJO_URL means
    # the forge is remote and no mapping is needed.
    read -r FORGEJO_URL SAME_HOST_HOSTNAMES <<< "$(network_shape)"
    if [ -z "$FORGEJO_URL" ] && [ -z "$SAME_HOST_HOSTNAMES" ]; then
      echo "ERROR: FORGEJO_URL is empty (same-host forge) but SAME_HOST_HOSTNAMES" >&2
      echo "  is empty in $WORKLOAD_INSTANCE_DIR/workload.toml — list the forge's" >&2
      echo "  ROOT_URL host there (e.g. forge.local) or the guest cannot reach" >&2
      echo "  Forgejo's action URLs." >&2
      exit 1
    fi
    RUNNER_PATH="$(runner_scope)"
    RUNNERS_URL="${FORGEJO_ADMIN_URL}/api/v1/${RUNNER_PATH}/actions/runners"
    ADMIN_TOKEN="$(systemd-creds decrypt "$ADMIN_CRED" -)"

    prune_stale

    # Create the runner on the server and take its credentials back. This is
    # the modern flow: POST .../actions/runners {name, ephemeral} ->
    # {id, uuid, token}. Both predecessors are deprecated — the
    # GET .../registration-token endpoint, and `forgejo-runner register` itself
    # (v13: "declare connections in the runner configuration instead") — so
    # neither is used. The runner's identity is the uuid+token pair; the seed
    # declares it as a server connection.
    # The token goes to curl via stdin (`-H @-`), never argv: argv is visible
    # in `ps` to every user on the host.
    response="$(printf 'Authorization: token %s\n' "$ADMIN_TOKEN" | \
                curl -fsS -X POST -H @- \
                  -H "Content-Type: application/json" \
                  -d "{\"name\": \"${RUNNER_NAME}\", \"ephemeral\": false}" \
                  "$RUNNERS_URL")"
    uuid="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("uuid",""))')"
    token="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')"
    if [ -z "$uuid" ] || [ -z "$token" ]; then
      echo "ERROR: Forgejo did not return a runner uuid+token; got:" >&2
      printf '%s\n' "$response" >&2
      exit 1
    fi

    # Seal each under the name the seed's ${SECRET?...} resolves. systemd-creds
    # binds the plaintext to the name, so seal name and credstore basename must
    # agree. mkdir first: systemd-creds will not create the credstore directory,
    # and a host that has never run `secret create` does not have one. Both
    # values are single-line, so they splice into the seed's write_files
    # safely — a raw multi-line secret would break the block scalar.
    install -d -m 0700 /etc/credstore.encrypted
    printf '%s' "$uuid"  | systemd-creds encrypt --name=forgejo-runner-uuid  - "$UUID_CRED"
    printf '%s' "$token" | systemd-creds encrypt --name=forgejo-runner-token - "$TOKEN_CRED"
    chmod 0600 "$UUID_CRED" "$TOKEN_CRED"
    echo "  registered runner ${RUNNER_NAME} for ${RUNNER_PATH} on" \
         "${FORGEJO_ADMIN_URL} (connection declared in the seed)"
    ;;

  disable)
    rm -f "$UUID_CRED" "$TOKEN_CRED"
    ;;

  artifacts)
    # Read-only, one "kind ref" per line. See host_setup.run_host_setup. Written
    # as an `if`, not `[ -e ] && echo`: under `set -e` a false test would become
    # the script's exit status and read as "does not implement the action".
    if [ -e "$TOKEN_CRED" ]; then
      echo "file $TOKEN_CRED"
    fi
    if [ -e "$UUID_CRED" ]; then
      echo "file $UUID_CRED"
    fi
    ;;

  *)
    echo "usage: $0 {enable|disable|artifacts}" >&2
    exit 1
    ;;
esac
