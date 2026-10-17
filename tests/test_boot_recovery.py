"""Boot/DNS recovery regression tests. All filesystem and service actions are isolated.

No root, systemd daemon, network, package install or VPS access is used here.
Real systemd boot-order and service retry acceptance belongs in a disposable VM/container.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()
BLOCK = SOURCE.split("# BEGIN BOOT_RECOVERY\n", 1)[1].split("# END BOOT_RECOVERY", 1)[0]
HELPER = subprocess.check_output(["bash", "-c", BLOCK + "\nboot_recovery_emit_helper"], text=True)


def function(name):
    return re.findall(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", SOURCE, re.M | re.S)[-1]


class BootRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.etc = self.root / "etc"
        self.etc.mkdir()
        self.calls = self.root / "calls"
        self.helper = self.root / "helper.sh"
        self.helper.write_text(HELPER)
        self.env = dict(os.environ, TEST_ROOT=str(self.root), TEST_ETC=str(self.etc),
                        CALLS=str(self.calls))

    def run_helper(self, code):
        harness = f"source {shlex.quote(str(self.helper))}\n" + r'''
BR_ETC="$TEST_ETC"
BR_RUN="$TEST_ROOT/run"
BR_BACKUPS="$TEST_ROOT/backups"
# No real time or network: emulate polling time without hiding tested return codes.
sleep() { SECONDS=$((SECONDS + 1)); }
timeout() { shift; "$@"; }
getent() { printf 'getent %s\n' "$*" >> "$CALLS"; return 0; }
ss() { return 0; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$CALLS"; return 91; }
flock() { return 0; }
''' + code
        return subprocess.run(["bash", "-c", harness], env=self.env, text=True,
                              capture_output=True, timeout=10)

    def run_block(self, code):
        # Redirect only the fixed backup root; every destination is a fixture path.
        block = BLOCK.replace("/var/backups/net-tcp-boot-recovery", str(self.root / "backups"))
        return subprocess.run(["bash", "-c", block + "\n" + code], env=self.env,
                              text=True, capture_output=True, timeout=10)

    def resolv(self, text="nameserver 8.8.8.8\n"):
        (self.etc / "resolv.conf").write_text(text)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def calls_text(self):
        return self.calls.read_text() if self.calls.exists() else ""

    def test_emitted_helper_has_valid_bash_syntax(self):
        self.assert_ok(subprocess.run(["bash", "-n", str(self.helper)], text=True, capture_output=True))

    def test_missing_stub_blocks_even_if_nss_would_resolve(self):
        (self.etc / "resolv.conf").symlink_to(self.etc / "not-created-yet")
        result = self.run_helper("br_wait_dns 2")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("getent", self.calls_text())

    def test_polling_waits_for_file_and_real_lookup(self):
        code = r'''
sleep() {
    SECONDS=$((SECONDS + 1))
    if [ "$SECONDS" -ge 2 ]; then printf 'nameserver 8.8.8.8\n' > "$BR_ETC/resolv.conf"; fi
}
br_wait_dns 5
'''
        self.assert_ok(self.run_helper(code))
        self.assertIn("getent ahosts", self.calls_text())

    def test_unserved_loopback_blocks_despite_nss_success(self):
        self.resolv("nameserver 127.0.0.53\n")
        result = self.run_helper("br_wait_dns 2")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("getent", self.calls_text())

    def test_scoped_loopback_socket_and_fallback_nameserver(self):
        self.resolv("nameserver 127.0.0.53\n")
        self.assert_ok(self.run_helper(r'''
ss() { printf 'udp UNCONN 0 0 127.0.0.53%%lo:53 0.0.0.0:*\n'; }
br_wait_dns 2
'''))
        self.resolv("nameserver 127.0.0.1\nnameserver 1.1.1.1\n")
        self.assert_ok(self.run_helper("br_wait_dns 2"))

    def test_lookup_failure_is_not_reported_as_success(self):
        self.resolv()
        result = self.run_helper("getent() { return 2; }; br_wait_dns 2")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS not ready", result.stderr)

    def test_ipv6_only_dns_and_lookup_are_accepted(self):
        self.resolv("nameserver 2001:4860:4860::8888\n")
        code = r'''
getent() {
    [ "$1" = ahosts ] || return 2
    printf '2001:db8::1 STREAM test-domain\n'
}
br_wait_dns 2
'''
        self.assert_ok(self.run_helper(code))

    def test_dns_restore_can_find_an_ipv6_only_default_route(self):
        self.resolv("nameserver 2001:4860:4860::8888\n")
        code = r'''
ip() { [ "$1" != -6 ] || echo 'default via 2001:db8::1 dev eth0'; }
resolvectl() { printf 'resolvectl %s\n' "$*" >> "$CALLS"; }
br_restore_dns 2001:4860:4860::8888 2606:4700:4700::1111 3
'''
        self.assert_ok(self.run_helper(code))
        self.assertIn("resolvectl dns eth0 2001:4860", self.calls_text())

    def test_dns_restore_missing_route_returns_failure(self):
        result = self.run_helper("ip() { :; }; resolvectl() { echo unexpected >> \"$CALLS\"; }; br_restore_dns 8.8.8.8 1.1.1.1 2")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("unexpected", self.calls_text())

    def test_dns_restore_retries_failed_configuration(self):
        self.resolv()
        code = r'''
ip() { echo 'default via 192.0.2.1 dev eth0'; }
resolvectl() {
    printf 'resolvectl %s\n' "$*" >> "$CALLS"
    if [ "$1" = dns ] && [ ! -f "$TEST_ROOT/tried" ]; then touch "$TEST_ROOT/tried"; return 1; fi
    return 0
}
br_restore_dns 8.8.8.8 1.1.1.1 5
'''
        self.assert_ok(self.run_helper(code))
        self.assertEqual(self.calls_text().count("resolvectl dns eth0"), 2)
        self.assertIn("DNS restored and verified", self.run_helper(code).stderr)

    def test_dns_restore_does_not_hide_persistent_resolver_failure(self):
        self.resolv()
        code = "ip() { echo 'default via 192.0.2.1 dev eth0'; }; resolvectl() { return 1; }; br_restore_dns 8.8.8.8 1.1.1.1 2"
        result = self.run_helper(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS restore failed", result.stderr)

    def test_invalid_dns_address_is_never_executed(self):
        result = self.run_helper("br_restore_dns '$(touch /unreachable-command)' 1.1.1.1 2")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls_text(), "")

    def dbus_file(self, custom=""):
        path = self.etc / "systemd/system/systemd-resolved.service.d/dbus-fix.conf"
        path.parent.mkdir(parents=True)
        text = """# Debian 13 D-Bus接口注册修复
# 确保D-Bus完全启动后再启动systemd-resolved
[Unit]
After=dbus.service
Requires=dbus.service

[Service]
# 启动后等待1秒，确保D-Bus接口注册完成
ExecStartPost=/bin/sleep 1
""" + custom
        path.write_text(text)
        return path

    def test_exact_legacy_dropin_is_backed_up_and_removed(self):
        path = self.dbus_file()
        original = path.read_bytes()
        self.assert_ok(self.run_helper("br_migrate_resolved"))
        self.assertFalse(path.exists())
        backups = list((self.root / "backups").glob("repair.*/dbus-fix.conf"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)

    def test_customized_dropin_is_preserved_without_service_actions(self):
        path = self.dbus_file("Environment=KEEP_ME=1\n")
        original = path.read_bytes()
        self.assertNotEqual(self.run_helper("br_migrate_resolved").returncode, 0)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.calls_text(), "")

    def test_symlink_dropin_does_not_delete_target(self):
        path = self.dbus_file()
        target = self.root / "target"
        path.rename(target)
        path.symlink_to(target)
        self.assertNotEqual(self.run_helper("br_migrate_resolved").returncode, 0)
        self.assertTrue(path.is_symlink())
        self.assertTrue(target.is_file())

    def test_uninstall_removes_only_exact_guard_and_preserves_other_overrides(self):
        directory = self.etc / "systemd/system/snell-15479.service.d"
        directory.mkdir(parents=True)
        guard = directory / "90-net-tcp-boot-recovery.conf"
        guard.write_text("""# NET_TCP_BOOT_RECOVERY_V1
[Unit]
After=network-online.target nss-lookup.target systemd-resolved.service dns-purify-persist.service
Wants=network-online.target
[Service]
ExecStartPre=/usr/local/libexec/net-tcp-boot-recovery --wait-dns 40
""")
        custom = directory / "operator.conf"
        custom.write_text("[Service]\nEnvironment=KEEP_ME=1\n")
        self.assert_ok(self.run_helper("br_remove_app_guards"))
        self.assertFalse(guard.exists())
        self.assertTrue(custom.is_file())
        self.assertTrue(self.helper.exists())

    def test_uninstall_keeps_modified_guard_and_shared_helper(self):
        directory = self.etc / "systemd/system/xray.service.d"
        directory.mkdir(parents=True)
        guard = directory / "90-net-tcp-boot-recovery.conf"
        original = "# NET_TCP_BOOT_RECOVERY_V1\n[Service]\nExecStartPre=/custom/operator-check\n"
        guard.write_text(original)
        self.assertNotEqual(self.run_helper("br_remove_app_guards").returncode, 0)
        self.assertEqual(guard.read_text(), original)
        self.assertTrue(self.helper.exists())

    def interfaces(self, main, child=None):
        directory = self.etc / "network/interfaces.d"
        directory.mkdir(parents=True)
        path = self.etc / "network/interfaces"
        path.write_text(main.replace("FIXTURE_ETC", str(self.etc)))
        if child:
            (directory / "50-cloud-init").write_text(child)
        return path

    def test_ipv6_conflict_is_found_through_source_without_editing_ipv4(self):
        self.interfaces("source FIXTURE_ETC/network/interfaces.d/*\n", "iface eth0 inet static\n address 192.0.2.2/24\niface eth0 inet6 static\n address 2001:db8::2/64\n")
        before = {p: p.read_bytes() for p in self.etc.rglob("*") if p.is_file()}
        result = self.run_helper("br_check_ifupdown_ipv6")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("50-cloud-init", result.stderr)
        self.assertEqual(before, {p: p.read_bytes() for p in self.etc.rglob("*") if p.is_file()})

    def test_ipv4_only_and_commented_ipv6_are_accepted(self):
        self.interfaces("source-directory FIXTURE_ETC/network/interfaces.d\n", "iface eth0 inet static\n address 192.0.2.2/24\n# iface eth0 inet6 static\n")
        self.assert_ok(self.run_helper("br_check_ifupdown_ipv6"))

    def test_unknown_include_is_refused_without_eval(self):
        self.interfaces("source $UNKNOWN_NETWORK_CONFIG\n")
        result = self.run_helper("br_check_ifupdown_ipv6")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unresolved include", result.stderr)

    def watch_code(self, enabled=True, active=True, selected="127.0.0.1"):
        return r'''
br_wait_dns() { return 0; }
br_snell_units() { echo snell-15479.service; }
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$CALLS"
    case "$1" in
        is-enabled) [ ENABLED_RC -ne 0 ] || echo enabled; return ENABLED_RC;;
        is-active) return ACTIVE_RC;;
        show) printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n';;
        --no-block) [ "$2" = try-restart ] || return 99;;
        *) return 99;;
    esac
}
journalctl() { printf 'Effective IPv4 DNS: 127.0.0.1\nEffective IPv4 DNS: SELECTED\n'; }
br_watch
'''.replace("ENABLED_RC", "0" if enabled else "1").replace("ACTIVE_RC", "0" if active else "1").replace("SELECTED", selected)

    def test_watch_recovers_only_enabled_active_stale_resolver_once(self):
        self.assert_ok(self.run_helper(self.watch_code()))
        self.assertEqual(self.calls_text().count("--no-block try-restart snell-15479.service"), 1)
        self.assert_ok(self.run_helper(self.watch_code()))
        self.assertEqual(self.calls_text().count("--no-block try-restart snell-15479.service"), 1)

    def test_watch_preserves_manual_stop_and_disabled_states(self):
        for enabled, active in ((False, True), (True, False), (False, False)):
            with self.subTest(enabled=enabled, active=active):
                self.assert_ok(self.run_helper(self.watch_code(enabled, active)))
        self.assertNotIn("try-restart", self.calls_text())

    def test_watch_static_unit_is_not_treated_as_enabled(self):
        code = self.watch_code().replace("echo enabled", "echo static")
        self.assert_ok(self.run_helper(code))
        self.assertNotIn("try-restart", self.calls_text())

    def test_watch_restart_budget_is_finite(self):
        state = self.root / "run"
        state.mkdir()
        code = r'''
printf '%s 2\n' "$(( $(date +%s) - 301 ))" > "$BR_RUN/snell-15479.service.attempts"
''' + self.watch_code()
        self.assert_ok(self.run_helper(code))
        self.assertNotIn("try-restart", self.calls_text())

    def test_watch_uses_latest_dns_line_for_current_invocation(self):
        self.assert_ok(self.run_helper(self.watch_code(selected="127.0.0.53")))
        self.assertNotIn("try-restart", self.calls_text())

    def test_external_dns_failure_does_not_restart_snell(self):
        code = self.watch_code().replace("br_wait_dns() { return 0; }", "br_wait_dns() { return 1; }")
        self.assertNotEqual(self.run_helper(code).returncode, 0)
        self.assertNotIn("snell-15479.service", self.calls_text())

    def test_patch_enumeration_does_not_start_or_enable_stopped_services(self):
        code = r'''
systemctl() {
    [ "$1" = list-unit-files ] || { echo forbidden >> "$CALLS"; return 99; }
    printf 'snell-15479.service enabled enabled\nsnell-15480.service disabled enabled\nxray.service enabled enabled\nxray@.service disabled enabled\n'
}
boot_recovery_patch_unit() { printf 'patched %s\n' "$1" >> "$CALLS"; }
boot_recovery_patch_enabled_units
'''
        self.assert_ok(self.run_block(code))
        self.assertEqual(self.calls_text(), "patched snell-15479.service\npatched xray.service\n")

    def test_custom_managed_filename_is_not_overwritten(self):
        path = self.root / "custom.conf"
        original = b"[Service]\nEnvironment=KEEP_ME=1\n"
        path.write_bytes(original)
        code = 'printf "# NET_TCP_BOOT_RECOVERY_V1\\nreplacement\\n" | boot_recovery_put "$TEST_ROOT/custom.conf" 644'
        self.assertNotEqual(self.run_block(code).returncode, 0)
        self.assertEqual(path.read_bytes(), original)

    def test_matching_comment_does_not_authorize_custom_dns_script_migration(self):
        apply = self.root / "dns-purify-apply.sh"
        unit = self.root / "dns-purify-persist.service"
        original = '# 由 net-tcp-tune.sh DNS净化功能自动生成\nDNS_PRIMARY="8.8.8.8"\nDNS_SECONDARY="1.1.1.1"\n# Custom operator modifications must be preserved\n'
        apply.write_text(original)
        unit.write_text("custom unit\n")
        block = BLOCK.replace("/usr/local/bin/dns-purify-apply.sh", str(apply)).replace(
            "/etc/systemd/system/dns-purify-persist.service", str(unit))
        result = subprocess.run(["bash", "-c", block + "\nboot_recovery_write_dns_service 8.8.8.8 1.1.1.1"],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(apply.read_text(), original)
        self.assertEqual(unit.read_text(), "custom unit\n")

    def test_legacy_dns_menu_change_validates_old_values_before_replacing(self):
        apply = self.root / "dns-purify-apply.sh"
        unit = self.root / "dns-purify-persist.service"
        # Reconstruct the published legacy fixture, without running its commands.
        head = BLOCK.split("cat <<'LEGACY_DNS_HEAD'\n", 1)[1].split("\nLEGACY_DNS_HEAD", 1)[0]
        body = BLOCK.split("cat <<'LEGACY_DNS_BODY'\n", 1)[1].split("\nLEGACY_DNS_BODY", 1)[0]
        original = head + '\nDNS_PRIMARY="8.8.8.8"\nDNS_SECONDARY="1.1.1.1"\n' + body + "\n"
        apply.write_text(original)
        block = BLOCK.replace("/usr/local/bin/dns-purify-apply.sh", str(apply)).replace(
            "/etc/systemd/system/dns-purify-persist.service", str(unit)).replace(
            "/var/backups/net-tcp-boot-recovery", str(self.root / "backups"))
        result = subprocess.run(["bash", "-c", block + "\nboot_recovery_write_dns_service 9.9.9.9 149.112.112.112"],
                                env=self.env, text=True, capture_output=True)
        self.assert_ok(result)
        self.assertIn('DNS_PRIMARY="9.9.9.9"', apply.read_text())
        self.assertIn('DNS_SECONDARY="149.112.112.112"', apply.read_text())
        self.assertIn("Restart=on-failure", unit.read_text())
        self.assertIn(original, [p.read_text() for p in (self.root / "backups").rglob("*") if p.is_file()])

    def test_modified_legacy_dns_body_is_preserved_when_switching_servers(self):
        apply = self.root / "dns-purify-apply.sh"
        head = BLOCK.split("cat <<'LEGACY_DNS_HEAD'\n", 1)[1].split("\nLEGACY_DNS_HEAD", 1)[0]
        body = BLOCK.split("cat <<'LEGACY_DNS_BODY'\n", 1)[1].split("\nLEGACY_DNS_BODY", 1)[0]
        original = head + '\nDNS_PRIMARY="8.8.8.8"\nDNS_SECONDARY="1.1.1.1"\n' + body + "\n# operator addition\n"
        apply.write_text(original)
        block = BLOCK.replace("/usr/local/bin/dns-purify-apply.sh", str(apply)).replace(
            "/etc/systemd/system/dns-purify-persist.service", str(self.root / "unit"))
        result = subprocess.run(["bash", "-c", block + "\nboot_recovery_write_dns_service 9.9.9.9 149.112.112.112"],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(apply.read_text(), original)

    def test_cli_dispatch_precedes_user_config_and_menu(self):
        home = self.root / "home"
        home.mkdir()
        (home / ".net-tcp-tune.conf").write_text('echo forbidden-config >> "$CALLS"\n')
        code = function("parse_args") + "\n" + function("main") + r'''
check_root() { :; }
run_boot_recovery_repair() { echo repair >> "$CALLS"; }
show_main_menu() { echo forbidden-menu >> "$CALLS"; return 99; }
HOME="$TEST_ROOT/home"
main --repair-boot-recovery
'''
        result = subprocess.run(["bash", "-c", code], env=self.env, text=True, capture_output=True)
        self.assert_ok(result)
        self.assertEqual(self.calls_text(), "repair\n")


if __name__ == "__main__":
    unittest.main()
