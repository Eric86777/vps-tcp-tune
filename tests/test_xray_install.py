"""Xray config ownership regression and opt-in real official install.

Config tests only modify disposable trees, with real UID access checks on Linux.
The complete installer test MUST run in an owned disposable systemd container:
  XRAY_REAL_INSTALL_TEST=1 python3 -m unittest discover -s tests -p test_xray_install.py -v
It also requires /.dockerenv and /root/xray-install-isolated-container. It downloads
and executes the official installer, installs Xray, and starts actual services.
Never enable that test on a VPS.
"""
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()


def function(name):
    return re.findall(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", SOURCE, re.M | re.S)[-1]


@unittest.skipUnless(os.geteuid() == 0 and Path("/proc").exists(), "Real Linux UID access needs root in disposable container")
class ConfigOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        self.path = self.root / "config.json"
        self.path.write_text('{"previous":true}\n')
        self.path.chmod(0o640)
        self.original = self.path.read_bytes()
        self.user = "nobody"
        self.dynamic = "no"
        self.loaded = "loaded"

    def save(self, extra="", action="xray_save_config '{\"new\":true}'"):
        stub = """
error() { printf '%s\\n' "$*" >&2; }
systemctl() {
    case "$*" in
      *LoadState*) printf '%s\\n' "$TEST_LOADED";;
      *DynamicUser*) printf '%s\\n' "$TEST_DYNAMIC";;
      *User*) printf '%s\\n' "$TEST_USER";;
      *) return 95;;
    esac
}
"""
        env = dict(os.environ, TEST_USER=self.user, TEST_DYNAMIC=self.dynamic, TEST_LOADED=self.loaded)
        code = stub + function("xray_save_config") + "\n" + function("write_config")
        code += "\nxray_config_path=" + shlex.quote(str(self.path)) + "\n" + extra + "\n" + action
        return subprocess.run(["bash", "-c", code], env=env, text=True, capture_output=True, timeout=10)

    def assert_private_owner(self, uid):
        metadata = self.path.stat()
        self.assertEqual(metadata.st_uid, uid)
        self.assertEqual(metadata.st_gid, 0)
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o640)
        self.assertEqual(list(self.root.glob("config.json.tmp.*")), [])

    def test_current_official_xray_user_can_read_private_config(self):
        try:
            account = pwd.getpwnam("xray")
        except KeyError:
            self.skipTest("Create non-root xray fixture account in isolated container")
        self.assertNotEqual(account.pw_uid, 0)
        self.user = "xray"
        result = self.save()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_owner(account.pw_uid)
        result = subprocess.run(["runuser", "-u", "xray", "--", "cat", str(self.path)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        other = subprocess.run(["runuser", "-u", "nobody", "--", "cat", str(self.path)], capture_output=True)
        self.assertNotEqual(other.returncode, 0)

    def test_legacy_nobody_unit_keeps_read_access(self):
        result = self.save()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_owner(pwd.getpwnam("nobody").pw_uid)
        result = subprocess.run(["runuser", "-u", "nobody", "--", "cat", str(self.path)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_user_means_systemd_root(self):
        self.user = ""
        result = self.save()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_owner(0)

    def test_numeric_service_uid_is_supported(self):
        self.user = str(pwd.getpwnam("nobody").pw_uid)
        result = self.save()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private_owner(int(self.user))

    def test_unknown_user_retains_original(self):
        self.user = "no_such_xray_fixture_user"
        self.assertNotEqual(self.save().returncode, 0)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_invalid_user_retains_original(self):
        self.user = "xray; touch bad"
        self.assertNotEqual(self.save().returncode, 0)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_dynamic_user_retains_original(self):
        self.dynamic = "yes"
        self.assertNotEqual(self.save().returncode, 0)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_unloaded_unit_retains_original(self):
        self.loaded = "not-found"
        self.assertNotEqual(self.save().returncode, 0)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_symlink_target_is_not_overwritten(self):
        target = self.root / "target"
        target.write_bytes(self.original)
        self.path.unlink()
        self.path.symlink_to(target)
        self.assertNotEqual(self.save().returncode, 0)
        self.assertEqual(target.read_bytes(), self.original)
        self.assertTrue(self.path.is_symlink())

    def test_failed_metadata_change_retains_original_and_removes_temp(self):
        self.assertNotEqual(self.save("chown() { return 87; }").returncode, 0)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(list(self.root.glob("config.json.tmp.*")), [])

    def test_write_config_preserves_custom_outbound_and_uses_effective_uid(self):
        self.path.write_text(json.dumps({"inbounds":[{"protocol":"vless"}],
            "outbounds":[{"protocol":"socks","tag":"socks5-existing"}],
            "routing":{"rules":[{"type":"field","inboundTag":["node"],"outboundTag":"socks5-existing"}]}}))
        result = self.save(action='write_config \'[{"protocol":"vless","tag":"node"}]\' false')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.path.read_text())
        self.assertEqual(config["outbounds"][-1]["tag"], "socks5-existing")
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "socks5-existing")
        self.assert_private_owner(pwd.getpwnam("nobody").pw_uid)


class WriterCoverageTests(unittest.TestCase):
    def test_all_three_config_writers_share_runtime_ownership(self):
        for name in ("write_config", "add_socks5_proxy", "delete_socks5_proxy"):
            body = function(name)
            self.assertIn("xray_save_config", body)
            self.assertNotIn("chown nobody", body)


class DependencyPreflightTests(unittest.TestCase):
    def test_unsupported_python_stops_before_boot_or_official_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            old_python = Path(directory) / "old-python"
            old_python.write_text("#!/bin/sh\nexit 1\n")
            old_python.chmod(0o755)
            changed = Path(directory) / "changed"
            code = function("ensure_xray_dependencies").replace("/usr/bin/python3", str(old_python))
            code += "\n" + function("run_core_install") + "\n" + r'''
command() { if [ "$1" = -v ]; then return 0; else builtin command "$@"; fi; }
require_no_xray_transaction() { return 0; }
error() { printf '%s\n' "$*" >&2; }
info() { :; }
boot_recovery_migrate() { touch "$TEST_CHANGED"; }
execute_official_script() { touch "$TEST_CHANGED"; }
run_core_install
'''
            result = subprocess.run(["bash", "-c", code], text=True, capture_output=True,
                env=dict(os.environ, TEST_CHANGED=str(changed)), timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Python 3.8", result.stderr)
            self.assertFalse(changed.exists())


REAL_ENABLED = (os.environ.get("XRAY_REAL_INSTALL_TEST") == "1" and os.geteuid() == 0
    and Path("/.dockerenv").exists() and Path("/root/xray-install-isolated-container").is_file()
    and Path("/proc/1/comm").read_text().strip() == "systemd")


def real_vless_install_code():
    boot = SOURCE.split("# BEGIN BOOT_RECOVERY\n", 1)[1].split("# END BOOT_RECOVERY", 1)[0]
    safe = "run_xray_safe_uninstall() {" + SOURCE.split("run_xray_safe_uninstall() {", 1)[1].split("\nrun_xinchendahai_xray()", 1)[0]
    embedded = SOURCE.split("<< 'XRAY_ENHANCED_SCRIPT_EOF'\n", 1)[1].split("\nXRAY_ENHANCED_SCRIPT_EOF", 1)[0].rsplit('\nmain "$@"', 1)[0]
    code = "set -euo pipefail\nexport TERM=xterm\n" + boot + "\n" + safe + "\n" + embedded
    code += """
get_public_ip() { printf '127.0.0.1\\n'; }
view_all_info() { printf 'VLESS_CONFIGURED_NO_CREDENTIAL_OUTPUT\\n'; }
ensure_xray_dependencies
run_install_vless 443 11111111-1111-4111-8111-111111111111 addons.mozilla.org isolated-fresh-install
systemctl is-active --quiet xray.service
test "$(systemctl is-enabled xray.service)" = enabled
test "$(systemctl show xray.service -p User --value)" = xray
runuser -u xray -- /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
"""
    return code


@unittest.skipUnless(REAL_ENABLED, "Opt-in owned disposable systemd container only")
class RealOfficialInstallTests(unittest.TestCase):
    def test_fresh_official_install_with_restricted_existing_libexec(self):
        self.assertFalse(Path("/usr/local/bin/xray").exists(), "Requires fresh owned container")
        libexec = Path("/usr/local/libexec")
        libexec.mkdir(exist_ok=True)
        libexec.chmod(0o700)
        code = real_vless_install_code()
        result = subprocess.run(["bash"], input=code, text=True, capture_output=True, timeout=420)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
        config = Path("/usr/local/etc/xray/config.json")
        self.assertEqual(config.stat().st_uid, pwd.getpwnam("xray").pw_uid)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(libexec.stat().st_mode), 0o711)
        self.assertEqual(json.loads(config.read_text())["inbounds"][0]["protocol"], "vless")


LEGACY_ENABLED = (os.environ.get("XRAY_REAL_LEGACY_TEST") == "1" and os.geteuid() == 0
    and Path("/.dockerenv").exists() and Path("/root/xray-install-isolated-container").is_file()
    and Path("/proc/1/comm").read_text().strip() == "systemd")


@unittest.skipUnless(LEGACY_ENABLED, "Opt-in owned disposable systemd container only")
class RealLegacyUpgradeTests(unittest.TestCase):
    def test_official_reinstall_migrates_nobody_without_changing_config(self):
        # Run after the fresh-install fixture, only in its disposable container.
        # --reinstall forces the real installer path even when already latest.
        config = Path("/usr/local/etc/xray/config.json")
        original = config.read_bytes()
        self.assertEqual(json.loads(original)["inbounds"][0]["protocol"], "vless")
        subprocess.run(["systemctl", "stop", "xray.service"], check=True)
        for name in ("xray.service", "xray@.service"):
            unit = Path("/etc/systemd/system") / name
            unit.write_text(unit.read_text().replace("User=xray", "User=nobody").replace("Group=xray", "Group=nogroup"))
        os.chown(config, pwd.getpwnam("nobody").pw_uid, 0)
        config.chmod(0o640)
        for name in ("/usr/local/share/xray", "/var/log/xray"):
            directory = Path(name)
            os.chown(directory, 0, 0)
            directory.chmod(0o755)
            for item in directory.iterdir():
                self.assertTrue(item.is_file() and not item.is_symlink())
                os.chown(item, 0, 0)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "start", "xray.service"], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", "xray.service"], check=True)
        boot = SOURCE.split("# BEGIN BOOT_RECOVERY\n", 1)[1].split("# END BOOT_RECOVERY", 1)[0]
        safe = "run_xray_safe_uninstall() {" + SOURCE.split("run_xray_safe_uninstall() {", 1)[1].split("\nrun_xinchendahai_xray()", 1)[0]
        embedded = SOURCE.split("<< 'XRAY_ENHANCED_SCRIPT_EOF'\n", 1)[1].split("\nXRAY_ENHANCED_SCRIPT_EOF", 1)[0].rsplit('\nmain "$@"', 1)[0]
        code = "set -euo pipefail\nexport TERM=xterm\n" + boot + "\n" + safe + "\n" + embedded
        code += r'''
eval "$(declare -f execute_official_script | sed '1s/execute_official_script/real_execute_official_script/')"
execute_official_script() {
    if [ "$1" = install ]; then real_execute_official_script 'install --reinstall'
    else real_execute_official_script "$1"; fi
}
ensure_xray_dependencies
run_core_install
restart_xray
systemctl is-active --quiet xray.service
test "$(systemctl is-enabled xray.service)" = enabled
test "$(systemctl show xray.service -p User --value)" = xray
runuser -u xray -- /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
'''
        result = subprocess.run(["bash"], input=code, text=True, capture_output=True, timeout=420)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual(config.stat().st_uid, pwd.getpwnam("xray").pw_uid)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)


class InstallCompletionTests(unittest.TestCase):
    def complete(self, enable_status=0, enabled="enabled"):
        code = function("xray_start_completed_install") + r'''
error() { printf '%s\n' "$*" >&2; }
systemctl() {
    case "$1" in
      enable) echo ENABLE; return "$ENABLE_STATUS";;
      is-enabled) echo "$ENABLED_STATE";;
      *) return 95;;
    esac
}
restart_xray() { echo RESTART; }
xray_start_completed_install
'''
        return subprocess.run(["bash", "-c", code], env=dict(os.environ,
            ENABLE_STATUS=str(enable_status), ENABLED_STATE=enabled), capture_output=True, text=True)

    def test_explicit_install_finishes_enable_before_restart(self):
        result = self.complete()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["ENABLE", "RESTART"])

    def test_failed_enable_does_not_restart_or_report_complete(self):
        result = self.complete(enable_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("RESTART", result.stdout)

    def test_disabled_result_does_not_restart_or_report_complete(self):
        result = self.complete(enabled="disabled")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("RESTART", result.stdout)

    def test_vless_ss_and_dual_install_finish_enable_but_update_does_not(self):
        for name in ("run_install_vless", "run_install_ss", "run_install_dual"):
            self.assertIn("xray_start_completed_install", function(name))
        self.assertNotIn("xray_start_completed_install", function("update_xray"))


RETRY_ENABLED = (os.environ.get("XRAY_REAL_RETRY_TEST") == "1" and os.geteuid() == 0
    and Path("/.dockerenv").exists() and Path("/root/xray-install-isolated-container").is_file()
    and Path("/proc/1/comm").read_text().strip() == "systemd")


@unittest.skipUnless(RETRY_ENABLED, "Opt-in owned disposable systemd container only")
class RealInterruptedInstallTests(unittest.TestCase):
    def test_retry_after_203_finishes_enable_when_core_already_latest(self):
        # Reproduce the user's halfway state: official files exist, initial
        # start failed before enable, and no VLESS configuration was generated.
        subprocess.run(["systemctl", "stop", "xray.service"], check=True)
        subprocess.run(["systemctl", "disable", "xray.service"], check=True, capture_output=True)
        config = Path("/usr/local/etc/xray/config.json")
        config.write_bytes(b"{}\n")
        os.chown(config, 0, 0)
        config.chmod(0o644)
        Path("/usr/local/libexec").chmod(0o700)
        # Inactive units may be garbage-collected after disable; start loads it.
        subprocess.run(["systemctl", "reset-failed", "xray.service"], capture_output=True)
        subprocess.run(["systemctl", "start", "xray.service"], capture_output=True)
        status = subprocess.check_output(["systemctl", "show", "xray.service", "-p", "ExecStartPre", "--value"], text=True)
        self.assertIn("status=203", status)
        subprocess.run(["systemctl", "stop", "xray.service"], check=True)
        subprocess.run(["systemctl", "reset-failed", "xray.service"], capture_output=True)
        result = subprocess.run(["bash"], input=real_vless_install_code(), capture_output=True, text=True, timeout=420)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
        self.assertEqual(config.stat().st_uid, pwd.getpwnam("xray").pw_uid)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertEqual(json.loads(config.read_text())["inbounds"][0]["protocol"], "vless")
