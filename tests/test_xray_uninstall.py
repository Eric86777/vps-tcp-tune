"""Fault tests for the published embedded helper, using only disposable trees.

Run under root in an isolated Linux container:
  useradd --system --user-group --no-create-home --home-dir /var/empty xray
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
from unittest import mock

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
OFFICIAL_XRAY_UNIT = """[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=xray
Group=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
UMask=0077
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755
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

    def official_owned_layout(self):
        try:
            account = MODULE.pwd.getpwnam("xray")
        except KeyError:
            self.fail("Create the dedicated xray account in the disposable test container first")
        self.assertNotEqual(account.pw_uid, 0)
        self.assertNotEqual(account.pw_gid, 0)
        self.env.write("/etc/systemd/system/xray.service", OFFICIAL_XRAY_UNIT)
        self.env.write("/etc/systemd/system/xray@.service", OFFICIAL_XRAY_UNIT.replace(
            "config.json", "%i.json").replace("RuntimeDirectory=xray\n", "RuntimeDirectory=xray-%i\n"))
        self.env.properties["xray.service"] = {"User": "xray", "Group": "xray"}
        for name, mode in (("/usr/local/share/xray", 0o755), ("/var/log/xray", 0o700)):
            path = self.env.path(name)
            for item in [path, *path.iterdir()]:
                os.chown(item, account.pw_uid, account.pw_gid)
                item.chmod(mode if item == path else 0o600 if name == "/var/log/xray" else 0o644)
        return account

    def stage_official_owned_layout(self, phase="moving"):
        account = self.official_owned_layout()
        self.env.record_install()
        plan = self.env.preflight()
        self.assertEqual(plan["data_uid"], account.pw_uid)
        plan["restore_files"] = {}
        for name in plan["paths"]:
            plan["restore_files"].update(self.env.tree(name))
        self.env.state_prepare()
        (self.env.state / "files").mkdir(mode=0o700)
        self.env.command("stop", "xray.service")
        self.env.command("disable", "--no-reload", "xray.service")
        for i, name in enumerate(plan["paths"]):
            os.rename(self.env.path(name), self.env.staged(i))
        data = {"version": 1, "phase": phase, "plan": plan}
        self.env.save(data)
        return data

    def fresh_fixture_environment(self):
        fresh = FakeEnvironment.__new__(FakeEnvironment)
        MODULE.Environment.__init__(fresh, self.directory.name)
        for name in ("home", "answers", "active", "enabled", "properties", "fail", "mount_points",
                     "extra_processes", "snell_changed", "interrupt_move"):
            setattr(fresh, name, copy.deepcopy(getattr(self.env, name)))
        fresh.calls = []
        return fresh

    def test_official_owned_directories_record_check_and_uninstall(self):
        account = self.official_owned_layout()
        self.env.record_install()
        before = self.env.tree("/")
        self.env.uninstall(check=True)
        self.assertEqual(self.env.tree("/"), before)
        self.assertEqual(self.env.calls, [])
        self.assertEqual(self.env.preflight()["data_uid"], account.pw_uid)
        self.env.uninstall()
        for name in MODULE.XRAY_DATA_DIRS:
            self.assertFalse(self.env.path(name).exists())
        self.assert_snell()

    def test_official_owned_directories_cancel_restores_exact_metadata(self):
        self.official_owned_layout()
        self.env.record_install()
        for active, enabled in ((True, "enabled"), (False, "disabled")):
            with self.subTest(active=active, enabled=enabled):
                self.env.active["xray.service"] = active
                self.env.enabled["xray.service"] = enabled
                if not active:
                    self.env.path("/etc/systemd/system/multi-user.target.wants/xray.service").unlink()
                before = {name: self.env.tree(name) for name in self.env.candidates()}
                calls_before = len(self.env.calls)
                self.env.answers = ["卸载Xray", ""]
                with self.assertRaises(MODULE.Refused):
                    self.env.uninstall()
                self.assertEqual({name: self.env.tree(name) for name in self.env.candidates()}, before)
                self.assertEqual(self.env.active["xray.service"], active)
                self.assertEqual(self.env.enabled["xray.service"], enabled)
                if not active:
                    self.assertNotIn(("start", "xray.service"), self.env.calls[calls_before:])
                self.assertIsNone(self.env.read_state())
                self.assert_snell()

    def test_official_owned_interrupted_transaction_recovers_without_live_units(self):
        data = self.stage_official_owned_layout()
        self.assertFalse(self.env.path("/etc/systemd/system/xray.service").exists())
        fresh = self.fresh_fixture_environment()
        fresh.answers = ["恢复Xray"]
        fresh.recover(rollback=True)
        restored = {}
        for name in data["plan"]["paths"]:
            restored.update(fresh.tree(name))
        self.assertEqual(restored, data["plan"]["restore_files"])
        self.assertTrue(fresh.active["xray.service"])
        self.assertEqual(fresh.enabled["xray.service"], "enabled")
        self.assertIsNone(fresh.read_state())
        self.assert_snell()

    def test_official_owned_interrupted_transaction_can_resume_purge(self):
        self.stage_official_owned_layout(phase="verifying")
        fresh = self.fresh_fixture_environment()
        fresh.answers = ["继续清理", "Snell已验证"]
        fresh.recover()
        self.assertIsNone(fresh.read_state())
        self.assertFalse((fresh.state / "files").exists())
        for name in fresh.candidates():
            self.assertFalse(fresh.path(name).exists())
        self.assert_snell()

    def test_official_owned_staged_metadata_changes_refuse_restore(self):
        data = self.stage_official_owned_layout()
        index = data["plan"]["paths"].index("/var/log/xray")
        staged = self.env.staged(index)
        original = staged.stat()
        for owner, mode in ((0, 0o700), (original.st_uid, 0o777)):
            with self.subTest(owner=owner, mode=mode):
                os.chown(staged, owner, original.st_gid)
                staged.chmod(mode)
                with self.assertRaises(MODULE.Refused):
                    self.env.validate_staged(data)
                self.assertTrue(staged.exists())
                os.chown(staged, original.st_uid, original.st_gid)
                staged.chmod(original.st_mode & 0o777)
        (staged / "error.log").write_text("tampered")
        with self.assertRaises(MODULE.Refused):
            self.env.validate_staged(data)
        self.assertTrue(staged.exists())
        self.assert_snell()

    def test_official_owned_directories_require_verified_unit_and_dedicated_data_account(self):
        account = self.official_owned_layout()
        # Official install-geodata is independent of the legacy runtime UID.
        for user, group in (("nobody", "nogroup"), ("xray", "root"), ("root", "root")):
            with self.subTest(user=user, group=group):
                self.env.properties["xray.service"].update(User=user, Group=group)
                self.env.uninstall(check=True)
        self.env.write("/etc/systemd/system/xray.service", OFFICIAL_XRAY_UNIT + "ExecStop=/usr/bin/true\n")
        self.assert_refused_without_mutations()
        self.env.write("/etc/systemd/system/xray.service", OFFICIAL_XRAY_UNIT)
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError("xray")):
            self.assert_refused_without_mutations()
        with mock.patch.object(MODULE.pwd, "getpwnam", return_value=types.SimpleNamespace(pw_uid=0, pw_gid=account.pw_gid)):
            self.assert_refused_without_mutations()

    def test_official_owned_exceptions_never_extend_to_parents_or_other_paths(self):
        account = self.official_owned_layout()
        for name in ("/usr/local", "/usr/local/share", "/var/log", MODULE.STATE, "/opt/xray"):
            with self.subTest(name=name):
                path = self.env.path(name)
                path.mkdir(parents=True, exist_ok=True)
                original = path.stat()
                os.chown(path, account.pw_uid, account.pw_gid)
                with self.assertRaises(MODULE.Refused):
                    self.env.safe_path(name, data_uid=account.pw_uid)
                os.chown(path, original.st_uid, original.st_gid)
        self.assertEqual(self.env.calls, [])
        self.assert_snell()

    def test_official_owned_directories_reject_unsafe_owner_modes_links_and_mounts(self):
        account = self.official_owned_layout()
        path = self.env.path("/usr/local/share/xray")
        wrong_uid = account.pw_uid + 10000
        for uid, mode in ((wrong_uid, 0o755), (account.pw_uid, 0o775), (account.pw_uid, 0o777)):
            with self.subTest(uid=uid, mode=mode):
                os.chown(path, uid, account.pw_gid)
                path.chmod(mode)
                self.assert_refused_without_mutations()
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o755)
        item = path / "geoip.dat"
        item.chmod(0o666)
        self.assert_refused_without_mutations()
        item.chmod(0o644)
        os.chown(item, wrong_uid, account.pw_gid)
        self.assert_refused_without_mutations()
        os.chown(item, account.pw_uid, account.pw_gid)
        self.env.mount_points = ["/usr/local/share/xray"]
        self.assert_refused_without_mutations()
        self.env.mount_points = []
        item.unlink()
        item.symlink_to(self.env.path("/etc/snell/snell-server.conf"))
        self.assert_refused_without_mutations()
        item.unlink()
        os.link(self.env.path("/etc/snell/snell-server.conf"), item)
        self.assert_refused_without_mutations()
        item.unlink()
        shutil.rmtree(path)
        path.symlink_to(self.env.path("/etc/snell"))
        self.assert_refused_without_mutations()

    def test_root_owned_legacy_layout_does_not_require_xray_account(self):
        with mock.patch.object(MODULE.pwd, "getpwnam", side_effect=KeyError("xray")):
            self.env.record_install()
            self.env.uninstall(check=True)
        self.assertEqual(self.env.calls, [])
        self.assert_snell()

    def test_managed_dns_guard_allows_uninstall_and_preserves_shared_helper(self):
        self.add_dns_guard()
        helper = self.env.tree(DNS_HELPER_PATH)
        self.env.uninstall()
        self.assertFalse(self.env.path(DNS_GUARD_PATH).exists())
        self.assertEqual(self.env.tree(DNS_HELPER_PATH), helper)
        self.assert_snell()

    def test_new_application_dns_guard_is_supported_without_loosening_exact_template(self):
        self.add_dns_guard()
        self.env.path(DNS_GUARD_PATH).write_text(DNS_GUARD.replace("--wait-dns 40", "--prepare-app-dns 40"))
        self.env.properties["xray.service"]["ExecStartPre"] = DNS_PRE.replace("--wait-dns 40", "--prepare-app-dns 40")
        self.env.uninstall(check=True)
        self.assertEqual(self.env.calls, [])
        self.env.path(DNS_GUARD_PATH).write_text(DNS_GUARD.replace("--wait-dns 40", "--prepare-app-dns 41"))
        self.assert_refused_without_mutations()

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

    def test_daemon_reload_cached_snell_exec_fields_do_not_block_safe_uninstall(self):
        unit = "snell-12345.service"
        command = self.env.show(unit)["ExecStart"].rsplit(" ;", 1)[0]
        running = command + " ; start_time=[Tue 2026-10-20 00:00:00 UTC] ; stop_time=[n/a] ; pid=2345 ; code=(null) ; status=0/0 }"
        reloaded = command + " ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        self.env.properties[unit] = {"ExecStart": running}
        self.snell = self.env.snell_snapshot()
        execute = self.env.command
        def reload_changes_cached_fields(*args, **kwargs):
            if args[0] == "daemon-reload":
                self.env.properties[unit]["ExecStart"] = reloaded
            return execute(*args, **kwargs)
        self.env.command = reload_changes_cached_fields
        self.env.uninstall()
        self.assert_snell()

    def test_snell_argv_runtime_like_literals_are_preserved(self):
        unit = "snell-12345.service"
        for argument in ("prefix ; status=1 ; suffix",
                         "prefix ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=1 ; code=(null) ; status=0/0 } suffix"):
            with self.subTest(argument=argument):
                command = ("{ path=/usr/local/bin/snell-server ; argv[]=/usr/local/bin/snell-server -c " + argument +
                    " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=2345 ; code=(null) ; status=0/0 }")
                self.env.properties[unit] = {"ExecStart": command}
                before = self.env.snell_snapshot()
                self.env.properties[unit]["ExecStart"] = command.replace("status=1", "status=2", 1) if "status=1" in argument else command.replace("pid=1", "pid=2", 1)
                with self.assertRaises(MODULE.Refused):
                    self.env.check_snell(before)

    def test_snell_configured_command_and_process_identity_still_block_cleanup(self):
        unit = "snell-12345.service"
        command = self.env.show(unit)["ExecStart"]
        self.env.properties[unit] = {"ExecStart": command}
        before = self.env.snell_snapshot()
        for changed in (command.replace(" -c ", " --changed -c "),
                        command.replace("/usr/local/bin/snell-server", "/usr/local/bin/snell-server-v6"),
                        command.replace("ignore_errors=no", "ignore_errors=yes")):
            with self.subTest(command=changed):
                self.env.properties[unit]["ExecStart"] = changed
                with self.assertRaises(MODULE.Refused):
                    self.env.check_snell(before)
        self.env.properties[unit]["ExecStart"] = command
        self.env.snell_changed = True
        with self.assertRaises(MODULE.Refused):
            self.env.check_snell(before)

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

    def test_current_official_units_record_and_readonly_check(self):
        for mask in ("0077", "077"):
            with self.subTest(mask=mask):
                unit = OFFICIAL_XRAY_UNIT.replace("UMask=0077", "UMask=" + mask)
                self.env.write("/etc/systemd/system/xray.service", unit)
                self.env.write("/etc/systemd/system/xray@.service", unit.replace(
                    "config.json", "%i.json").replace("RuntimeDirectory=xray\n", "RuntimeDirectory=xray-%i\n"))
                self.env.record_install()
                self.assertTrue(self.env.path(MODULE.INSTALL_RECORD).is_file())
                before = self.env.tree("/")
                self.env.uninstall(check=True)
                self.assertEqual(self.env.tree("/"), before)
                self.assertEqual(self.env.calls, [])
                self.assert_snell()

    def test_install_record_does_not_bypass_uninstall_mask_checks(self):
        for mask in ("0000", "0022", "0070", "00077", "77", "0o077", "u=rwx", "", "0078"):
            with self.subTest(mask=mask):
                self.env.write("/etc/systemd/system/xray.service", OFFICIAL_XRAY_UNIT.replace(
                    "UMask=0077", "UMask=" + mask))
                self.env.record_install()
                before = self.env.tree("/")
                self.assert_refused_without_mutations()
                self.assertEqual(self.env.tree("/"), before)

    def test_install_record_does_not_bypass_uninstall_hook_checks(self):
        for hook in ("ExecStartPre=/usr/bin/true", "ExecStop=/usr/bin/true", "ExecStartPost=/usr/bin/true"):
            with self.subTest(hook=hook):
                self.env.write("/etc/systemd/system/xray.service", OFFICIAL_XRAY_UNIT.replace(
                    "[Service]\n", "[Service]\n" + hook + "\n"))
                self.env.record_install()
                before = self.env.tree("/")
                self.assert_refused_without_mutations()
                self.assertEqual(self.env.tree("/"), before)

    def test_legacy_nobody_units_still_record_and_readonly_check(self):
        self.env.record_install()
        before = self.env.tree("/")
        self.env.uninstall(check=True)
        self.assertEqual(self.env.tree("/"), before)
        self.assertEqual(self.env.calls, [])
        self.assert_snell()

    def test_legacy_unit_with_official_xray_owned_data_records_and_uninstalls(self):
        self.official_owned_layout()
        self.env.write("/etc/systemd/system/xray.service", UNIT)
        self.env.write("/etc/systemd/system/xray@.service", UNIT.replace("config.json", "%i.json"))
        self.env.properties["xray.service"] = {"User": "nobody", "Group": "nogroup"}
        self.env.record_install()
        self.env.uninstall()
        self.assertFalse(self.env.path("/usr/local/bin/xray").exists())
        self.assert_snell()

    def test_resource_dropin_does_not_block_nondestructive_install_record(self):
        self.official_owned_layout()
        extra = "/etc/systemd/system/xray.service.d/resources.conf"
        self.env.write(extra, "[Service]\nCPUQuota=50%\nMemoryMax=512M\n")
        self.env.properties["xray.service"]["DropInPaths"] = extra
        before = self.env.tree("/etc/systemd/system")
        self.env.record_install()
        self.assertEqual(self.env.tree("/etc/systemd/system"), before)
        self.assertEqual(self.env.calls, [])
        # A successful install record must not weaken the destructive unit check.
        self.assert_refused_without_mutations()

    def test_supported_ss_and_dual_protocol_uninstall_including_backups(self):
        for protocols in (("shadowsocks",), ("vless", "shadowsocks")):
            with self.subTest(protocols=protocols), tempfile.TemporaryDirectory() as directory:
                self.env = FakeEnvironment(directory)
                self.snell = self.env.snell_snapshot()
                config = json.dumps({"inbounds": [{"protocol": p} for p in protocols]})
                self.env.write("/usr/local/etc/xray/config.json", config)
                self.env.write("/usr/local/etc/xray/config.json.bak.20261020", config)
                self.env.write("/root/xray_subscription_info.txt", "\n".join(
                    ("vless://dummy" if p == "vless" else "ss://dummy") for p in protocols) + "\n")
                self.env.uninstall()
                self.assertFalse(self.env.path("/usr/local/bin/xray").exists())
                self.assertFalse(self.env.path("/usr/local/etc/xray").exists())
                self.assertFalse(self.env.path("/root/xray_subscription_info.txt").exists())
                self.assert_snell()

    def test_official_copytruncate_logrotate_is_supported(self):
        self.env.write("/etc/logrotate.d/xray", "/var/log/xray/*.log {\n daily\n rotate 7\n missingok\n notifempty\n compress\n delaycompress\n copytruncate\n}\n")
        self.env.uninstall()
        self.assertFalse(self.env.path("/etc/logrotate.d/xray").exists())
        self.assert_snell()

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

    def test_unsupported_configuration_and_subscription_are_refused(self):
        config = self.env.path("/usr/local/etc/xray/config.json")
        config.write_text(json.dumps({"inbounds": [{"protocol": "vmess"}]}))
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
