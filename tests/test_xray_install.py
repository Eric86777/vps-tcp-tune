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


class VersionPolicyTests(unittest.TestCase):
    """Stable Xray core by default; upstream latest only after an explicit menu choice and confirmation."""

    POLICY = "\n".join([re.search(r"^readonly XRAY_PINNED_VERSION=.*$", SOURCE, re.M).group(),
                         'xray_chosen_version=""'] + [function(name) for name in (
                             "xray_target_version", "xray_version_gt", "xray_fetch_latest_version",
                             "xray_choose_version", "xray_newer_version_notice")])
    STUBS = r'''
cyan=''; none=''; green=''; yellow=''
info() { printf 'info %s\n' "$1"; }
success() { printf 'success %s\n' "$1"; }
warning() { printf 'warning %s\n' "$1"; }
error() { printf 'error %s\n' "$1"; }
draw_divider() { echo ---; }
curl() { [ -n "$TEST_LATEST" ] || return 22; printf '{"tag_name":"%s"}\n' "$TEST_LATEST"; }
'''

    def env(self, override=None, latest="v26.10.21", **extra):
        env = dict(os.environ, TEST_LATEST=latest, **extra)
        env.pop("XRAY_VERSION_OVERRIDE", None)
        if override is not None:
            env["XRAY_VERSION_OVERRIDE"] = override
        return env

    def target(self, override=None):
        env = dict(os.environ)
        env.pop("XRAY_VERSION_OVERRIDE", None)
        if override is not None:
            env["XRAY_VERSION_OVERRIDE"] = override
        return subprocess.run(["bash", "-c", self.POLICY + "\nxray_target_version"], env=env,
                              text=True, capture_output=True, timeout=10)

    def test_target_version_defaults_to_pin_and_accepts_overrides(self):
        for override, expected in ((None, "v26.3.27"), ("", "v26.3.27"), ("latest", ""),
                                   ("v26.10.21", "v26.10.21"), ("26.4.1", "v26.4.1")):
            with self.subTest(override=override):
                result = self.target(override)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_invalid_override_is_rejected(self):
        for override in ("bad;rm", "v26", "26.3.27 --reinstall", "../v1.2"):
            with self.subTest(override=override):
                result = self.target(override)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("XRAY_VERSION_OVERRIDE 格式无效", result.stderr)

    def update(self, current, stdin="", override=None, latest="v26.10.21"):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "xray"
            binary.write_text("#!/bin/sh\necho 'Xray " + current + " (Xray, Penetrates Everything.)'\n")
            binary.chmod(0o755)
            code = "set -euo pipefail\n" + self.POLICY + "\n" + function("update_xray") + "\n" + self.STUBS + r"""
xray_binary_path="$TEST_BINARY"
ensure_xray_dependencies() { return 0; }
boot_recovery_migrate() { return 0; }
run_core_install() { echo "CORE_INSTALL[${xray_chosen_version}]"; }
restart_xray() { echo RESTART; }
update_xray
"""
            return subprocess.run(["bash", "-c", code], input=stdin, env=self.env(override, latest, TEST_BINARY=str(binary)),
                                  text=True, capture_output=True, timeout=10)

    def test_update_default_keeps_stable_when_already_stable(self):
        result = self.update("26.3.27", stdin="\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("稳定版 26.3.27（推荐，默认），即当前版本", result.stdout)
        self.assertIn("官方最新版 26.10.21", result.stdout)
        self.assertIn("mihomo 内核需 v1.19.31 及以上", result.stdout)
        self.assertIn("已是 26.3.27，无需更新", result.stdout)
        self.assertNotIn("CORE_INSTALL", result.stdout)

    def test_update_older_than_stable_installs_stable_by_default(self):
        for stdin in ("\n", "1\n", ""):  # Enter, explicit 1, and EOF/non-interactive all mean default
            with self.subTest(stdin=stdin):
                result = self.update("26.2.6", stdin=stdin)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)
                self.assertIn("RESTART", result.stdout)

    def test_update_latest_requires_y_confirmation(self):
        result = self.update("26.3.27", stdin="2\ny\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CORE_INSTALL[v26.10.21]", result.stdout)
        for answer in ("2\nn\n", "2\n\n", "2\n"):
            with self.subTest(answer=answer):
                result = self.update("26.2.6", stdin=answer)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("已取消，改用稳定版 26.3.27", result.stdout)
                self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)

    def test_update_invalid_choice_asks_again(self):
        result = self.update("26.2.6", stdin="9\nabc\n1\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("无效选项"), 2)
        self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)

    def test_update_newer_than_stable_keeps_by_default(self):
        for stdin in ("\n", ""):
            with self.subTest(stdin=stdin):
                result = self.update("26.10.21", stdin=stdin)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("保持当前版本 26.10.21（默认）", result.stdout)
                self.assertIn("保持当前版本 26.10.21，未更新", result.stdout)
                self.assertNotIn("CORE_INSTALL", result.stdout)
                self.assertNotIn("RESTART", result.stdout)

    def test_update_newer_than_stable_can_downgrade_to_stable(self):
        result = self.update("26.10.21", stdin="2\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("降回稳定版 26.3.27", result.stdout)
        self.assertNotIn("官方最新版", result.stdout)  # latest == current: no third option
        self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)

    def test_update_newer_than_stable_offers_even_newer_latest(self):
        result = self.update("26.10.21", stdin="3\ny\n", latest="v26.11.1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CORE_INSTALL[v26.11.1]", result.stdout)
        result = self.update("26.10.21", stdin="3\nn\n", latest="v26.11.1")
        self.assertIn("已取消，保持当前版本 26.10.21", result.stdout)
        self.assertNotIn("CORE_INSTALL", result.stdout)

    def test_update_without_newer_latest_or_network_shows_no_menu(self):
        for latest, warned in (("", True), ("v26.3.27", False), ("v26.2.6", False), ("garbage;rm", True)):
            with self.subTest(latest=latest):
                result = self.update("26.2.6", latest=latest)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("请选择要安装的 Xray 版本", result.stdout)
                self.assertEqual("无法获取官方最新版本号" in result.stdout, warned)
                self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)

    def test_update_override_skips_menu_and_may_downgrade(self):
        result = self.update("26.10.21", override="v26.3.27")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("请选择要安装的 Xray 版本", result.stdout)
        self.assertIn("按 XRAY_VERSION_OVERRIDE 指定 Xray 版本", result.stdout)
        self.assertIn("CORE_INSTALL[v26.3.27]", result.stdout)

    def test_update_latest_override_keeps_upstream_latest_behavior(self):
        code_result = self.update("26.3.27", override="latest")
        self.assertEqual(code_result.returncode, 0, code_result.stdout + code_result.stderr)
        self.assertNotIn("请选择要安装的 Xray 版本", code_result.stdout)
        self.assertIn("最新版本: 26.10.21", code_result.stdout)
        self.assertIn("CORE_INSTALL[]", code_result.stdout)

    def test_update_invalid_override_stops_before_install(self):
        result = self.update("26.2.6", override="bad;rm")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CORE_INSTALL", result.stdout)

    def choose_install(self, current, stdin="", latest="v26.10.21"):
        code = "set -euo pipefail\n" + self.POLICY + "\n" + self.STUBS + r"""
xray_choose_version install "$TEST_CURRENT"
echo "CHOSEN[${xray_chosen_version}]"
"""
        return subprocess.run(["bash", "-c", code], input=stdin, env=self.env(None, latest, TEST_CURRENT=current),
                              text=True, capture_output=True, timeout=10)

    def test_install_defaults_to_stable_and_keeps_newer_installed_core(self):
        for current, stdin, chosen in (("", "\n", "v26.3.27"), ("", "2\ny\n", "v26.10.21"),
                                       ("26.10.21", "\n", "v26.10.21"), ("26.10.21", "2\n", "v26.3.27")):
            with self.subTest(current=current, stdin=stdin):
                result = self.choose_install(current, stdin)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("CHOSEN[" + chosen + "]", result.stdout)

    def test_install_entries_choose_version_before_any_prompt(self):
        for name in ("install_vless_only", "install_ss_only", "install_dual"):
            with self.subTest(name=name):
                self.assertRegex(function(name), r"^\w+\(\) \{\n    xray_choose_install_version \|\| return 1\n")

    def test_newer_core_notice_only_above_stable(self):
        for current, shown in (("26.10.21", True), ("26.3.27", False), ("26.2.6", False)):
            with self.subTest(current=current):
                with tempfile.TemporaryDirectory() as directory:
                    binary = Path(directory) / "xray"
                    binary.write_text("#!/bin/sh\necho 'Xray " + current + " (Xray)'\n")
                    binary.chmod(0o755)
                    code = "set -euo pipefail\n" + self.POLICY + "\n" + self.STUBS + '\nxray_binary_path="' + str(binary) + '"\nxray_newer_version_notice\necho DONE\n'
                    result = subprocess.run(["bash", "-c", code], text=True, capture_output=True, timeout=10)
                self.assertIn("DONE", result.stdout, result.stderr)
                self.assertEqual("需 mihomo v1.19.31 及以上" in result.stdout, shown)

    def run_core(self, override=None):
        code = self.POLICY + "\n" + function("run_core_install") + "\n" + r'''
info() { printf 'info %s\n' "$1"; }
error() { printf 'error %s\n' "$1"; }
ensure_xray_dependencies() { return 0; }
boot_recovery_migrate() { return 0; }
execute_official_script() { printf 'OFFICIAL[%s]\n' "$1"; [ "$1" = install-geodata ] || exit 0; }
run_core_install
'''
        env = dict(os.environ)
        env.pop("XRAY_VERSION_OVERRIDE", None)
        if override is not None:
            env["XRAY_VERSION_OVERRIDE"] = override
        return subprocess.run(["bash", "-c", code], env=env, text=True, capture_output=True, timeout=10)

    def test_core_install_uses_menu_choice_before_policy(self):
        code = self.POLICY + "\n" + function("run_core_install") + "\n" + r'''
info() { :; }
error() { printf 'error %s\n' "$1"; }
ensure_xray_dependencies() { return 0; }
boot_recovery_migrate() { return 0; }
execute_official_script() { printf 'OFFICIAL[%s]\n' "$1"; exit 0; }
xray_chosen_version=v26.10.21
run_core_install
'''
        result = subprocess.run(["bash", "-c", code], env=self.env(), text=True, capture_output=True, timeout=10)
        self.assertIn("OFFICIAL[install --version v26.10.21]", result.stdout, result.stderr)

    def test_core_install_passes_pinned_version_to_official_installer(self):
        for override, action in ((None, "install --version v26.3.27"),
                                 ("v26.10.21", "install --version v26.10.21"), ("latest", "install")):
            with self.subTest(override=override):
                result = self.run_core(override)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("OFFICIAL[" + action + "]", result.stdout)

    def test_core_install_invalid_override_never_runs_official_installer(self):
        result = self.run_core("bad;rm")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("OFFICIAL", result.stdout)

    def test_vless_link_requests_x25519mlkem768_for_mihomo(self):
        # Xray v26.10.21+ REALITY rejects Client Hellos without X25519MLKEM768; mihomo only sends it when asked.
        link = re.search(r'vless_url="vless://[^"]*"', function("view_all_info")).group()
        self.assertIn("&sid=${shortid}&support-x25519mlkem768=true#", link)

    def test_official_installer_receives_version_as_separate_arguments(self):
        # execute_official_script expands $args unquoted on purpose; confirm the split.
        self.assertRegex(function("execute_official_script"), r'bash "\$temp_script" \$args &')


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
