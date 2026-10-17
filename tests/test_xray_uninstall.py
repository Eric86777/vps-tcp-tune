"""Fault tests for the published embedded helper, using only disposable trees.

Run under root in an isolated Linux container:
  python3 -m unittest discover -s tests -p test_xray_uninstall.py -v
Actual systemd/Snell integration is covered by test_xray_systemd.py separately.
"""
import copy
import contextlib
import fcntl
import json
import io
import os
from pathlib import Path
import re
import shutil
import tempfile
import types
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()
CODE = SCRIPT.split("<<'XRAY_SAFE_UNINSTALL_PY'\n", 1)[1].split("\nXRAY_SAFE_UNINSTALL_PY", 1)[0]
MODULE = types.ModuleType("xray_uninstall_test")
exec(compile(CODE, "embedded-xray-uninstall", "exec"), MODULE.__dict__)

UNIT = """[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
User=nobody
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RuntimeDirectory=xray
[Install]
WantedBy=multi-user.target
"""
DNS_GUARD = """# NET_TCP_BOOT_RECOVERY_V1
[Unit]
After=network-online.target nss-lookup.target systemd-resolved.service dns-purify-persist.service
Wants=network-online.target
[Service]
ExecStartPre=/usr/local/libexec/net-tcp-boot-recovery --wait-dns 40
"""
DNS_GUARD_PATH = "/etc/systemd/system/xray.service.d/90-net-tcp-boot-recovery.conf"
DNS_HELPER_PATH = "/usr/local/libexec/net-tcp-boot-recovery"
DNS_PRE = "{ path=" + DNS_HELPER_PATH + " ; argv[]=" + DNS_HELPER_PATH + " --wait-dns 40 ; ignore_errors=no ; }"


class FakeEnvironment(MODULE.Environment):
    def __init__(self, root):
        super().__init__(root)
        self.home = "/root"
        self.calls = []
        self.answers = ["卸载Xray", "Snell已验证", "恢复Xray", "继续清理"]
        self.active = {"xray.service": True, "snell-12345.service": True}
        self.enabled = {"xray.service": "enabled", "snell-12345.service": "enabled"}
        self.properties = {}
        self.fail = set()
        self.mount_points = []
        self.extra_processes = []
        self.snell_changed = False
        self.interrupt_move = False
        self.prepare()

    def write(self, name, content):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return path

    def prepare(self):
        self.write("/usr/local/bin/xray", b"\x7fELFtest-core")
        self.write("/usr/local/etc/xray/config.json", json.dumps({"inbounds": [{"protocol": "vless"}]}))
        self.write("/usr/local/share/xray/geoip.dat", "geoip")
        self.write("/usr/local/share/xray/geosite.dat", "geosite")
        self.write("/var/log/xray/error.log", "log")
        self.write("/etc/systemd/system/xray.service", UNIT)
        self.write("/etc/systemd/system/xray@.service", UNIT.replace("config.json", "%i.json"))
        self.write("/etc/systemd/system/xray.service.d/override.conf", "[Service]\nRestart=always\n")
        self.write("/root/xray_subscription_info.txt", "vless://dummy\n")
        self.write("/etc/logrotate.d/xray", "/var/log/xray/*.log {\n daily\n}\n")
        self.write("/etc/snell/snell-server.conf", "listen=0.0.0.0:12345\npsk=dummy\n")
        self.write("/etc/snell-v6/snell-12346.conf", "dummy")
        self.write("/usr/local/bin/snell-server", "snell-core")
        self.write("/usr/local/bin/snell-server-v6", "snell-v6-core")
        self.write("/etc/systemd/system/snell-12345.service", "snell-service")
        link = self.path("/etc/systemd/system/multi-user.target.wants/xray.service")
        link.parent.mkdir()
        link.symlink_to("../xray.service")

    def units(self):
        return sorted(self.active)

    def show(self, name):
        if name not in self.active:
            return {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": ""}
        fragment = "/etc/systemd/system/" + ("xray@.service" if name.startswith("xray@") else name)
        exists = self.path(fragment).exists()
        is_snell = name.startswith("snell")
        command = "/usr/local/bin/snell-server -c /etc/snell/snell-server.conf" if is_snell else (
            "/usr/local/bin/xray run -config /usr/local/etc/xray/" + (name[5:-8] if name.startswith("xray@") else "config") + ".json")
        executable = "/usr/local/bin/snell-server" if is_snell else "/usr/local/bin/xray"
        result = {key: "" for key in MODULE.PROPS}
        result.update(Id=name, Names=name, LoadState="loaded" if exists else "not-found",
                      ActiveState="active" if self.active[name] else "inactive", SubState="running" if self.active[name] else "dead",
                      UnitFileState=self.enabled[name] if exists else "", MainPID="2345" if is_snell else "1234",
                      ExecMainStartTimestampMonotonic="100", FragmentPath=fragment if exists else "",
                      ExecStart="{ path=" + executable + " ; argv[]=" + command + " ; ignore_errors=no ; }",
                      DropInPaths="/etc/systemd/system/xray.service.d/override.conf" if name == "xray.service" and exists else "")
        result.update(self.properties.get(name, {}))
        return result

    def mounts(self):
        return self.mount_points

    def processes(self):
        output = [(2345, "/usr/local/bin/snell-server", "101" if self.snell_changed else "100")]
        if any(self.active.get(name) for name in self.active if name.startswith("xray")):
            output.append((1234, "/usr/local/bin/xray", "100"))
        return sorted(output + self.extra_processes)

    def listeners(self):
        return ['tcp LISTEN 0.0.0.0:12345 *:* users:(("snell-server",pid=2345,fd=3))']

    def confirm(self, phrase, message):
        answer = self.answers.pop(0) if self.answers else ""
        if answer != phrase:
            raise MODULE.Cancelled("操作已取消")

    def command(self, *args, ok=(0,)):
        self.calls.append(args)
        if args[0] in self.fail or tuple(args[:2]) in self.fail:
            self.fail.discard(args[0])  # fail once so rollback can be tested
            self.fail.discard(tuple(args[:2]))
            raise MODULE.Refused("injected " + args[0] + " failure")
        if args[0] == "stop":
            self.active[args[1]] = False
        elif args[0] == "disable":
            name = args[-1]
            self.enabled[name] = "disabled"
            for logical in list(self.links()):
                if Path(logical).name == name:
                    self.path(logical).unlink()
        elif args[0] == "start":
            self.active[args[1]] = True
        elif args[0] == "daemon-reload":
            for name in self.active:
                if name.startswith("xray"):
                    link = self.path("/etc/systemd/system/multi-user.target.wants/" + name)
                    if link.is_symlink():
                        self.enabled[name] = "enabled"
        return ""


@unittest.skipUnless(os.geteuid() == 0 and os.name == "posix", "Run these filesystem safety tests as root in an isolated Linux container")
class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.env = FakeEnvironment(self.directory.name)
        self.snell = self.env.snell_snapshot()

    def assert_snell(self):
        self.assertEqual(self.env.snell_snapshot(), self.snell)
        self.assertFalse(any(any("snell" in arg for arg in call[1:]) for call in self.env.calls))

    def assert_refused_without_mutations(self):
        with self.assertRaises(MODULE.Refused):
            self.env.uninstall()
        self.assertEqual(self.env.calls, [])
        self.assert_snell()

    def add_dns_guard(self):
        helper = self.env.write(DNS_HELPER_PATH, "#!/bin/bash\n# NET_TCP_BOOT_RECOVERY_V1 -- generated by net-tcp-tune.sh; no downloads.\nexit 0\n")
        helper.chmod(0o755)
        self.env.write(DNS_GUARD_PATH, DNS_GUARD)
        self.env.properties["xray.service"] = {
            "DropInPaths": "/etc/systemd/system/xray.service.d/override.conf " + DNS_GUARD_PATH,
            "ExecStartPre": DNS_PRE,
        }

    def test_managed_dns_guard_allows_uninstall_and_preserves_shared_helper(self):
        self.add_dns_guard()
        helper = self.env.tree(DNS_HELPER_PATH)
        self.env.uninstall()
        self.assertFalse(self.env.path(DNS_GUARD_PATH).exists())
        self.assertEqual(self.env.tree(DNS_HELPER_PATH), helper)
        self.assert_snell()

    def test_managed_dns_guard_client_cancel_restores_xray(self):
        self.add_dns_guard()
        before = self.env.tree("/usr/local")
        self.env.answers = ["卸载Xray", ""]
        with self.assertRaises(MODULE.Refused):
            self.env.uninstall()
        self.assertEqual(self.env.tree("/usr/local"), before)
        self.assertEqual(self.env.path(DNS_GUARD_PATH).read_text(), DNS_GUARD)
        self.assertTrue(self.env.active["xray.service"])
        self.assertIsNone(self.env.read_state())
        self.assert_snell()

    def test_managed_dns_guard_loaded_command_must_match_exactly(self):
        self.add_dns_guard()
        for command in (DNS_PRE.replace("--wait-dns 40", "--wait-dns 41"),
                        DNS_PRE + " " + DNS_PRE,
                        DNS_PRE.replace("ignore_errors=no", "ignore_errors=yes"),
                        DNS_PRE.replace(DNS_HELPER_PATH, "/usr/local/bin/operator-script")):
            with self.subTest(command=command):
                self.env.properties["xray.service"]["ExecStartPre"] = command
                self.assert_refused_without_mutations()

    def test_managed_dns_guard_custom_file_or_missing_loaded_path_refused(self):
        self.add_dns_guard()
        self.env.path(DNS_GUARD_PATH).write_text(DNS_GUARD + "ExecStartPre=/usr/bin/true\n")
        self.assert_refused_without_mutations()
        self.env.path(DNS_GUARD_PATH).write_text(DNS_GUARD)
        self.env.properties["xray.service"]["DropInPaths"] = "/etc/systemd/system/xray.service.d/override.conf"
        self.assert_refused_without_mutations()

    def test_managed_dns_guard_content_in_custom_filename_is_refused(self):
        self.add_dns_guard()
        self.env.path(DNS_GUARD_PATH).unlink()
        self.env.path("/etc/systemd/system/xray.service.d/override.conf").write_text(DNS_GUARD)
        self.env.properties["xray.service"]["DropInPaths"] = "/etc/systemd/system/xray.service.d/override.conf"
        self.assert_refused_without_mutations()

    def test_managed_dns_guard_helper_must_be_trusted_executable(self):
        self.add_dns_guard()
        helper = self.env.path(DNS_HELPER_PATH)
        for mode in (0o644, 0o777):
            with self.subTest(mode=mode):
                helper.chmod(mode)
                self.assert_refused_without_mutations()
        helper.unlink()
        self.assert_refused_without_mutations()
        helper.symlink_to(self.env.path("/usr/local/bin/snell-server"))
        self.assert_refused_without_mutations()
        helper.unlink()
        os.link(self.env.path("/usr/local/bin/snell-server"), helper)
        self.assert_refused_without_mutations()

    def test_default_uninstall_and_repeat(self):
        self.env.uninstall()
        self.assertFalse(self.env.path("/usr/local/bin/xray").exists())
        self.assertFalse(self.env.path("/usr/local/etc/xray").exists())
        self.assertFalse(self.env.path("/root/xray_subscription_info.txt").exists())
        self.assertIsNone(self.env.read_state())
        self.assert_snell()
        self.env.active.pop("xray.service")
        self.env.uninstall()
        self.assert_snell()

    def test_read_only_check_changes_no_files_or_services(self):
        before = self.env.tree("/")
        self.env.uninstall(check=True)
        self.assertEqual(self.env.tree("/"), before)
        self.assertEqual(self.env.calls, [])

    def test_all_nonexact_confirmation_inputs_cancel(self):
        for answer in ["", "y", "Y", "no", "n", "N", "mistyped"]:
            with self.subTest(answer=answer):
                self.env.answers = [answer]
                self.assert_refused_without_mutations()

    def test_client_confirmation_cancel_rolls_back(self):
        before = self.env.tree("/usr/local")
        self.env.answers = ["卸载Xray", ""]
        with self.assertRaises(MODULE.Refused):
            self.env.uninstall()
        self.assertEqual(self.env.tree("/usr/local"), before)
        self.assertTrue(self.env.active["xray.service"])
        self.assert_snell()

    def test_missing_binary_still_cleans_configuration(self):
        self.env.path("/usr/local/bin/xray").unlink()
        self.env.active["xray.service"] = False
        self.env.uninstall()
        self.assertFalse(self.env.path("/usr/local/etc/xray").exists())
        self.assert_snell()

    def test_missing_template_or_dropin_is_not_an_error(self):
        self.env.path("/etc/systemd/system/xray@.service").unlink()
        shutil.rmtree(self.env.path("/etc/systemd/system/xray.service.d"))
        self.env.properties["xray.service"] = {"DropInPaths": ""}
        self.env.uninstall()
        self.assert_snell()

    def test_orphan_binary_without_install_record_is_refused(self):
        self.env.path("/etc/systemd/system/xray.service").unlink()
        self.env.path("/etc/systemd/system/xray@.service").unlink()
        self.assert_refused_without_mutations()

    def test_non_vless_configuration_and_subscription_are_refused(self):
        config = self.env.path("/usr/local/etc/xray/config.json")
        config.write_text(json.dumps({"inbounds": [{"protocol": "shadowsocks"}]}))
        self.assert_refused_without_mutations()
        config.write_text(json.dumps({"inbounds": [{"protocol": "vless"}]}))
        self.env.path("/root/xray_subscription_info.txt").write_text("snell://dummy")
        self.assert_refused_without_mutations()

    def test_invalid_json_and_unknown_files_refused(self):
        config = self.env.path("/usr/local/etc/xray/config.json")
        config.write_text("broken")
        self.assert_refused_without_mutations()
        config.write_text("{}")
        self.env.write("/usr/local/share/xray/unrelated.txt", "not ours")
        self.assert_refused_without_mutations()

    def test_symlink_to_snell_refused(self):
        directory = self.env.path("/usr/local/etc/xray")
        shutil.rmtree(directory)
        directory.symlink_to(self.env.path("/etc/snell"))
        self.assert_refused_without_mutations()

    def test_nested_symlink_and_hardlink_refused(self):
        link = self.env.path("/usr/local/etc/xray/unsafe.json")
        link.symlink_to(self.env.path("/etc/snell/snell-server.conf"))
        self.assert_refused_without_mutations()
        link.unlink()
        os.link(self.env.path("/etc/snell/snell-server.conf"), link)
        self.assert_refused_without_mutations()

    def test_mount_refused(self):
        self.env.mount_points = ["/usr/local/etc/xray/nested"]
        self.assert_refused_without_mutations()

    def test_stop_hooks_aliases_and_reverse_dependencies_refused(self):
        for prop, value in [("ExecStop", "/usr/bin/evil"), ("ExecStartPre", "/usr/bin/evil"),
                            ("RequiredBy", "snell-12345.service"), ("BoundBy", "snell-12345.service"),
                            ("ConsistsOf", "snell-12345.service"), ("UpheldBy", "watchdog.service"),
                            ("Names", "xray.service snell.service")]:
            with self.subTest(prop=prop):
                self.env.properties["xray.service"] = {prop: value}
                self.assert_refused_without_mutations()

    def test_disk_and_loaded_execstart_mismatch_refused(self):
        self.env.properties["xray.service"] = {"ExecStart": "{ path=/usr/local/bin/snell-server ; argv[]=/usr/local/bin/snell-server ; }"}
        self.assert_refused_without_mutations()

    def test_also_directive_refused_before_disable(self):
        self.env.path("/etc/systemd/system/xray.service").write_text(UNIT + "Also=snell-12345.service\n")
        self.assert_refused_without_mutations()

    def test_unmanaged_process_refused(self):
        self.env.extra_processes = [(666, "/opt/custom/xray", "100")]
        self.assert_refused_without_mutations()

    def test_environment_variables_do_not_change_scope(self):
        old = {k: os.environ.get(k) for k in ("DAT_PATH", "JSON_PATH", "JSONS_PATH", "HOME")}
        try:
            for k in old:
                os.environ[k] = "/etc/snell"
            self.env.uninstall()
            self.assert_snell()
        finally:
            for k, value in old.items():
                os.environ.pop(k, None) if value is None else os.environ.__setitem__(k, value)

    def test_stop_disable_reload_failures_restore(self):
        for action in ["stop", "disable", "daemon-reload"]:
            with self.subTest(action=action):
                directory = tempfile.TemporaryDirectory()
                try:
                    env = FakeEnvironment(directory.name)
                    before = env.tree("/usr/local")
                    env.fail = {action}
                    with self.assertRaises(MODULE.Refused):
                        env.uninstall()
                    self.assertEqual(env.tree("/usr/local"), before)
                    self.assertTrue(env.active["xray.service"])
                    self.assertIsNone(env.read_state())
                finally:
                    directory.cleanup()

    def test_shared_logrotate_templates_preserved(self):
        timer = "[Unit]\nDescription=Run logrotate for %i logs\n[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n"
        service = "[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.d/%i\n"
        self.env.write("/etc/systemd/system/logrotate@.timer", timer)
        self.env.write("/etc/systemd/system/logrotate@.service", service)
        self.env.write("/etc/logrotate.d/snell", "snell policy")
        self.snell = self.env.snell_snapshot()
        self.env.uninstall()
        self.assertEqual(self.env.path("/etc/systemd/system/logrotate@.timer").read_text(), timer)
        self.assertEqual(self.env.path("/etc/systemd/system/logrotate@.service").read_text(), service)
        self.assertTrue(self.env.path("/etc/logrotate.d/snell").exists())
        self.assert_snell()

    def test_core_install_record_detects_changed_binary(self):
        self.env.record_install()
        self.env.path("/usr/local/bin/xray").write_bytes(b"\x7fELFchanged-core")
        self.assert_refused_without_mutations()

    def test_install_record_allows_orphan_core_cleanup(self):
        self.env.record_install()
        self.env.path("/etc/systemd/system/xray.service").unlink()
        self.env.path("/etc/systemd/system/xray@.service").unlink()
        self.env.active.pop("xray.service")
        self.env.path("/etc/systemd/system/multi-user.target.wants/xray.service").unlink()
        self.env.uninstall()
        self.assert_snell()

    def test_lock_blocks_concurrent_operation(self):
        fd = self.env.common_lock()
        try:
            with self.assertRaises(MODULE.Refused):
                self.env.common_lock()
        finally:
            os.close(fd)

    def test_corrupt_recovery_record_cannot_touch_snell(self):
        self.env.state_prepare()
        self.env.save({"version": 1, "phase": "moving", "plan": {"paths": ["/etc/snell"], "units": {}}})
        with self.assertRaises(MODULE.Refused):
            self.env.read_state()
        self.assert_snell()

    def test_summary_hardlink_cannot_overwrite_snell(self):
        self.env.state_prepare()
        os.link(self.env.path("/etc/snell/snell-server.conf"), self.env.state / "last-result.json")
        self.assert_refused_without_mutations()

    def test_new_original_file_blocks_rollback_without_overwrite(self):
        plan = self.env.preflight()
        plan["restore_files"] = {}
        for p in plan["paths"]:
            plan["restore_files"].update(self.env.tree(p))
        self.env.state_prepare()
        (self.env.state / "files").mkdir()
        index = plan["paths"].index("/usr/local/bin/xray")
        os.rename(self.env.path("/usr/local/bin/xray"), self.env.staged(index))
        self.env.write("/usr/local/bin/xray", b"\x7fELFnew-install")
        with self.assertRaises(MODULE.Refused):
            self.env.rollback({"version": 1, "phase": "moving", "plan": plan})
        self.assertEqual(self.env.path("/usr/local/bin/xray").read_bytes(), b"\x7fELFnew-install")

    def test_snell_change_is_detected_without_repairing_it(self):
        self.env.snell_changed = True
        with self.assertRaises(MODULE.Refused):
            self.env.check_snell(self.snell)
        self.assertEqual(self.env.calls, [])

    def test_recovery_staging_mount_or_content_change_refused(self):
        plan = self.env.preflight()
        plan["restore_files"] = {}
        for name in plan["paths"]:
            plan["restore_files"].update(self.env.tree(name))
        self.env.state_prepare()
        (self.env.state / "files").mkdir()
        for i, name in enumerate(plan["paths"]):
            os.rename(self.env.path(name), self.env.staged(i))
        data = {"version": 1, "phase": "verifying", "plan": plan}
        self.env.validate_staged(data)
        self.env.mount_points = [self.env.logical(self.env.staged(0))]
        with self.assertRaises(MODULE.Refused):
            self.env.validate_staged(data)
        self.env.mount_points = []
        self.env.staged(0).write_bytes(b"\x7fELFunexpected")
        with self.assertRaises(MODULE.Refused):
            self.env.validate_staged(data)
        self.assert_snell()

    def test_early_interruption_can_restore_and_retry(self):
        plan = self.env.preflight()
        plan["restore_files"] = {}
        for name in plan["paths"]:
            plan["restore_files"].update(self.env.tree(name))
        self.env.state_prepare()
        (self.env.state / "files").mkdir()
        os.rename(self.env.path(plan["paths"][0]), self.env.staged(0))
        self.env.save({"version": 1, "phase": "moving", "plan": plan})
        self.env.answers = ["恢复Xray"]
        self.env.recover(rollback=True)
        self.assertIsNone(self.env.read_state())
        self.env.answers = ["卸载Xray", "Snell已验证"]
        self.env.uninstall()
        self.assert_snell()

    def test_corrupt_recovery_link_target_is_refused(self):
        plan = self.env.preflight()
        plan["links"]["/etc/systemd/system/multi-user.target.wants/xray.service"] = "../snell-12345.service"
        self.env.state_prepare()
        self.env.save({"version": 1, "phase": "prepared", "plan": plan})
        with self.assertRaises(MODULE.Refused):
            self.env.read_state()
        self.assert_snell()

    def test_purge_failure_preserves_resume_record(self):
        original = MODULE.shutil.rmtree
        def fail(path):
            if str(path).startswith(str(self.env.state)):
                raise OSError("injected purge failure")
            return original(path)
        MODULE.shutil.rmtree = fail
        try:
            with self.assertRaises(MODULE.Refused):
                self.env.uninstall()
        finally:
            MODULE.shutil.rmtree = original
        self.assertEqual(self.env.read_state()["phase"], "purging")
        self.env.answers = ["继续清理"]
        self.env.recover()
        self.assertIsNone(self.env.read_state())
        self.assert_snell()

    def test_source_uninstall_has_no_network_fallback(self):
        function = re.search(r"^uninstall_xray\(\) \{\n.*?^\}", SCRIPT, re.M | re.S)[0]
        self.assertNotIn("execute_official_script", function)
        main = SCRIPT[SCRIPT.rindex("\nmain() {"):]
        self.assertNotIn("\n    auto_cleanup_legacy_mtu\n", main)
        self.assertNotIn("\n    cf_helper_migrate_legacy", main)


if __name__ == "__main__":
    unittest.main()
