"""Installer identity handoff in a disposable Linux container only.

Requires root, /.dockerenv, XRAY_INSTALLER_IDENTITY_TEST=1, a dedicated non-root
xray account and /root/xray-installer-identity-isolated-container. The systemctl
executable is mocked; real UID permissions and byte copies use the fixed default
Xray paths. No official download, real service or VPS is touched.
"""
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()
ENABLED = (os.geteuid() == 0 and Path("/.dockerenv").is_file() and
           os.environ.get("XRAY_INSTALLER_IDENTITY_TEST") == "1" and
           Path("/root/xray-installer-identity-isolated-container").is_file())
CONFIG = Path("/usr/local/etc/xray/config.json")


def body(name):
    match = re.search(r"^" + re.escape(name) + r"\(\) [({]\n.*?^[})]", SOURCE, re.M | re.S)
    if match is None:
        raise AssertionError("missing function " + name)
    return match.group()


@unittest.skipUnless(ENABLED, "Explicitly marked disposable Linux container only")
class InstallerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.account = pwd.getpwnam("xray")
        self.assertNotEqual(self.account.pw_uid, 0)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        self.user = self.root / "user"
        self.user.write_text("nobody\n")
        self.payload = self.root / "installer"
        self.env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"],
                        TEST_CALLS=str(self.calls), TEST_USER_STATE=str(self.user),
                        TEST_INSTALLER_PAYLOAD=str(self.payload), TEST_LOADED="loaded", TEST_DYNAMIC="no")
        if CONFIG.parent.is_symlink():
            CONFIG.parent.unlink()
        else:
            shutil.rmtree(CONFIG.parent, ignore_errors=True)
        CONFIG.parent.mkdir(parents=True, mode=0o755)
        CONFIG.parent.chmod(0o755)
        self.original = b'{"preserve":"all bytes"}\n\n\n'
        CONFIG.write_bytes(self.original)
        os.chown(CONFIG, pwd.getpwnam("nobody").pw_uid, 0)
        CONFIG.chmod(0o640)
        self.executable("systemctl", r'''#!/bin/bash
set -u
printf '%s\n' "$*" >> "$TEST_CALLS"
case "$*" in
  'show xray.service --property=LoadState --value') printf '%s\n' "$TEST_LOADED";;
  'show xray.service --property=DynamicUser --value') printf '%s\n' "$TEST_DYNAMIC";;
  'show xray.service --property=User --value') cat "$TEST_USER_STATE";;
  'start xray'|'start xray.service')
    runuser -u "$(cat "$TEST_USER_STATE")" -- test -r /usr/local/etc/xray/config.json;;
esac
''')

    def executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def script(self, action, quiet=False, extra=""):
        code = "set -u\n" + body("xray_sync_existing_config_owner") + "\n"
        code += body("spinner") + "\n" + body("execute_official_script") + "\n"
        code += '''
error() { printf '%s\\n' "$*" >&2; }
info() { :; }
success() { :; }
curl() { command cat "$TEST_INSTALLER_PAYLOAD"; }
xray_install_script_url=https://example.invalid/install-release.sh
'''
        code += "is_quiet=" + ("true" if quiet else "false") + "\n" + extra + "\n"
        code += "result=0\n" + action + " || result=$?\n"
        code += '''
if declare -F systemctl >/dev/null; then exit 91; fi
if export -pf | grep -Eq '^declare -fx (systemctl|xray_sync_existing_config_owner)$'; then exit 92; fi
exit "$result"
'''
        return subprocess.run(["bash", "-c", code], text=True, env=self.env,
                              capture_output=True, timeout=15)

    def installer(self, commands, quiet=False):
        self.payload.write_text("#!/bin/bash\n# install-release\nset -euo pipefail\n" + commands + "\n")
        return self.script("execute_official_script install", quiet=quiet)

    def assert_synced(self):
        self.assertEqual(CONFIG.read_bytes(), self.original)
        metadata = CONFIG.stat()
        self.assertEqual((metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
                         (self.account.pw_uid, 0, 0o640))
        self.assertEqual(list(CONFIG.parent.glob("config.json.owner.*")), [])

    def test_actual_uid_and_bytes_are_synced_before_both_supported_starts(self):
        for quiet, target in ((False, "xray"), (True, "xray.service")):
            with self.subTest(quiet=quiet, target=target):
                os.chown(CONFIG, pwd.getpwnam("nobody").pw_uid, 0)
                self.user.write_text("nobody\n")
                result = self.installer('declare -F systemctl >/dev/null\n'
                                        'declare -F xray_sync_existing_config_owner >/dev/null\n'
                                        'printf "xray\\n" > "$TEST_USER_STATE"\n'
                                        'systemctl start ' + target, quiet)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_synced()

    def test_installer_failure_propagates_for_quiet_and_normal_mode(self):
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                result = self.installer("exit 37", quiet)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(CONFIG.read_bytes(), self.original)

    def test_failed_copy_never_calls_start_or_changes_original(self):
        self.executable("cp", "#!/bin/sh\nexit 71\n")
        before = CONFIG.stat()
        for quiet in (False, True):
            with self.subTest(quiet=quiet):
                self.calls.unlink(missing_ok=True)
                result = self.installer('printf "xray\\n" > "$TEST_USER_STATE"\nsystemctl start xray', quiet)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("start xray", self.calls.read_text())
                self.assertEqual(CONFIG.read_bytes(), self.original)
                self.assertEqual(CONFIG.stat().st_uid, before.st_uid)
                self.assertEqual(list(CONFIG.parent.glob("config.json.owner.*")), [])

    def test_option_multiple_target_and_instance_starts_are_rejected(self):
        for command in ("systemctl --no-block start xray", "systemctl start xray --no-block",
                        "systemctl start xray snell.service", "systemctl start -- xray.service",
                        "systemctl start xray@one.service", "systemctl start xray@one",
                        "systemctl start 'xray*'", "systemctl start '*.service'",
                        "systemctl start snell.service xray.service"):
            with self.subTest(command=command):
                self.calls.unlink(missing_ok=True)
                result = self.installer(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())
                self.assertEqual(CONFIG.read_bytes(), self.original)

    def test_other_service_calls_are_forwarded_without_identity_change(self):
        result = self.installer("systemctl stop xray\nsystemctl start snell.service\nsystemctl enable xray")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), "stop xray\nstart snell.service\nenable xray\n")
        self.assertEqual(CONFIG.stat().st_uid, pwd.getpwnam("nobody").pw_uid)

    def test_invalid_dynamic_or_unloaded_identity_prevents_start(self):
        for user, loaded, dynamic in (("missing-xray-user", "loaded", "no"),
                                      ("bad user", "loaded", "no"),
                                      ("xray", "not-found", "no"), ("xray", "loaded", "yes")):
            with self.subTest(user=user, loaded=loaded, dynamic=dynamic):
                self.user.write_text(user + "\n")
                self.env.update(TEST_LOADED=loaded, TEST_DYNAMIC=dynamic)
                self.calls.unlink(missing_ok=True)
                result = self.installer("systemctl start xray")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("start xray", self.calls.read_text())
                self.assertEqual(CONFIG.read_bytes(), self.original)

    def test_unsafe_parent_and_linked_config_are_rejected_before_start(self):
        CONFIG.parent.chmod(0o777)
        result = self.installer("systemctl start xray")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        CONFIG.parent.chmod(0o755)
        CONFIG.unlink()
        outside = self.root / "outside"
        outside.write_bytes(self.original)
        CONFIG.symlink_to(outside)
        result = self.installer("systemctl start xray")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(outside.read_bytes(), self.original)
        CONFIG.unlink()
        os.link(outside, CONFIG)
        result = self.installer("systemctl start xray")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        CONFIG.unlink()
        CONFIG.parent.rmdir()
        outside_directory = self.root / "outside-directory"
        outside_directory.mkdir()
        CONFIG.parent.symlink_to(outside_directory)
        result = self.installer("systemctl start xray")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_missing_config_is_allowed_without_creating_anything(self):
        CONFIG.unlink()
        result = self.script("xray_sync_existing_config_owner")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(CONFIG.exists())
        self.assertFalse(self.calls.exists())

    def test_core_no_start_branch_still_syncs_before_registration(self):
        extra = body("run_core_install") + '''
boot_recovery_migrate() { return 0; }
execute_official_script() { printf 'xray\\n' > "$TEST_USER_STATE"; }
run_xray_safe_uninstall() { runuser -u xray -- test -r /usr/local/etc/xray/config.json; }
'''
        result = self.script("run_core_install", extra=extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_synced()


if __name__ == "__main__":
    unittest.main()
