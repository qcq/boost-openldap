#!/usr/bin/env python3

import os
import socket
import subprocess
import sys
import tempfile
import time

import ldap

URI = "ldap://127.0.0.1:1389"
BASE_DN = "dc=example,dc=com"
ADMIN_DN = "cn=admin," + BASE_DN
ADMIN_PASSWORD = "secret"


CONFIG = f"""\
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema

pidfile /tmp/boost-openldap-slapd.pid
argsfile /tmp/boost-openldap-slapd.args

database mdb
maxsize 1073741824
suffix \"{BASE_DN}\"
rootdn \"{ADMIN_DN}\"
rootpw {ADMIN_PASSWORD}
directory {{directory}}
index objectClass eq
"""


LDIF_BASE = [
    (BASE_DN, {
        "objectClass": [b"top", b"dcObject", b"organization"],
        "dc": [b"example"],
        "o": [b"Example Organization"],
    }),
]

LDIF_ALICE = [
    ("cn=alice," + BASE_DN, {
        "objectClass": [b"top", b"person", b"organizationalPerson", b"inetOrgPerson"],
        "cn": [b"alice"],
        "sn": [b"Alice"],
        "mail": [b"alice@example.com"],
    }),
]


def server_diagnostics(server: subprocess.Popen) -> str:
    returncode = server.poll()
    stderr = server.stderr.read() if server.stderr else ""
    stdout = server.stdout.read() if server.stdout else ""
    details = [f"slapd return code: {returncode}"]
    if stderr:
        details.append("slapd stderr:\n" + stderr)
    if stdout:
        details.append("slapd stdout:\n" + stdout)
    return "\n".join(details)


def wait_for_port(server: subprocess.Popen, host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        returncode = server.poll()
        if returncode is not None:
            raise RuntimeError("slapd exited before listening\n" + server_diagnostics(server))

        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)

    raise RuntimeError("slapd did not start listening in time\n" + server_diagnostics(server))


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-test_real_ldap>", file=sys.stderr)
        return 2

    cpp_test = os.path.abspath(sys.argv[1])

    with tempfile.TemporaryDirectory(prefix="boost-openldap-slapd-") as tmp:
        db_dir = os.path.join(tmp, "db")
        os.mkdir(db_dir)
        config_path = os.path.join(tmp, "slapd.conf")
        with open(config_path, "w", encoding="utf-8") as config:
            config.write(CONFIG.format(directory=db_dir))

        # The CI runner owns the temporary test tree. Explicitly keep slapd in
        # that same uid/gid instead of dropping privileges to the system
        # "openldap" account, which cannot traverse the runner's temp directory.
        slapd_uid = str(os.getuid())
        slapd_gid = str(os.getgid())
        server = subprocess.Popen(
            [
                "slapd",
                "-f", config_path,
                "-h", URI,
                "-u", slapd_uid,
                "-g", slapd_gid,
                "-d", "1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            wait_for_port(server, "127.0.0.1", 1389)

            # python-ldap is the independent reference client. It exercises the
            # same OpenLDAP client library family through Python before the C++
            # client talks to the exact same slapd instance.
            reference = ldap.initialize(URI)
            reference.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            reference.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)
            reference.simple_bind_s(ADMIN_DN, ADMIN_PASSWORD)

            for dn, attributes in LDIF_BASE + LDIF_ALICE:
                reference.add_s(dn, list(attributes.items()))

            results = reference.search_s(
                BASE_DN,
                ldap.SCOPE_SUBTREE,
                "(objectClass=inetOrgPerson)",
                ["cn", "mail"],
            )
            assert len(results) == 1, results
            assert results[0][0] == "cn=alice," + BASE_DN, results
            assert results[0][1]["cn"] == [b"alice"], results
            assert results[0][1]["mail"] == [b"alice@example.com"], results
            reference.unbind_s()

            # Now exercise the C++ asynchronous client against the real server.
            completed = subprocess.run([cpp_test, URI], check=False)
            return completed.returncode
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)

            if server.returncode not in (0, -15):
                stderr = server.stderr.read() if server.stderr else ""
                if stderr:
                    print(stderr, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
