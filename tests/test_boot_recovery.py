"""Boot/DNS recovery regression tests. All filesystem and service actions are isolated.

No root, systemd daemon, network, package install or VPS access is used here.
Real systemd boot-order and service retry acceptance belongs in a disposable VM/container.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import stat
import tempfile
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()
BLOCK = SOURCE.split("# BEGIN BOOT_RECOVERY\n", 1)[1].split("# END BOOT_RECOVERY", 1)[0]
HELPER = subprocess.check_output(["bash", "-c", BLOCK + "\nboot_recovery_emit_helper"], text=True)


def function(name):
    return re.findall(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}", SOURCE, re.M | re.S)[-1]


XRAY_VERSION_POLICY = "\n".join([re.search(r"^readonly XRAY_PINNED_VERSION=.*$", SOURCE, re.M).group(),
                                 'xray_chosen_version=""'] + [function(name) for name in (
                                     "xray_target_version", "xray_version_gt", "xray_fetch_latest_version",
                                     "xray_choose_version", "xray_newer_version_notice")])


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
BR_LOCAL="$TEST_ROOT/usr/local"
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
        # Temp files model root-owned project assets; ownership checks have a
        # separate Linux/metadata fixture and are not macOS user ownership here.
        trusted_fixture = '\nboot_recovery_trusted_file() { [ -f "$1" ] && [ ! -L "$1" ]; }\n'
        return subprocess.run(["bash", "-c", block + trusted_fixture + code], env=self.env,
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

    def test_domestic_dns_success_is_accepted_without_external_domains(self):
        self.resolv()
        self.assert_ok(self.run_helper('getent() { [ "$2" = www.baidu.com ]; }; br_wait_dns 6'))

    def test_single_lookup_can_use_four_second_fallback(self):
        self.resolv()
        code = r'''
# timeout subprocess needs an executable fixture, rather than a shell function.
printf '#!/bin/bash\n/bin/sleep 4\nexit 0\n' > "$TEST_ROOT/getent"
chmod +x "$TEST_ROOT/getent"
timeout() { python3 - "$1" "$TEST_ROOT/getent" <<'REAL_TIMEOUT'
import subprocess, sys
try:
    sys.exit(subprocess.run([sys.argv[2]], timeout=float(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
REAL_TIMEOUT
}
br_wait_dns 6
'''
        self.assert_ok(self.run_helper(code))

    def test_business_dns_prepare_warns_but_does_not_prevent_service_start(self):
        self.resolv()
        result = self.run_helper('getent() { return 2; }; br_prepare_app_dns 2')
        self.assert_ok(result)
        self.assertIn("business startup continues", result.stderr)

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

    def test_watch_rechecks_current_command_after_old_guard_was_installed(self):
        unit = "snell-15479.service"
        main = self.etc / "systemd/system" / unit
        main.parent.mkdir(parents=True)
        main.write_text("[Unit]\nDescription=Snell Proxy Service (Port15479)\n[Service]\nExecStart=/opt/unrelated/server\n")
        guard = main.parent / (unit + ".d/90-net-tcp-boot-recovery.conf")
        guard.parent.mkdir()
        guard.write_text("# NET_TCP_BOOT_RECOVERY_V1\n[Unit]\nAfter=network-online.target nss-lookup.target systemd-resolved.service dns-purify-persist.service\nWants=network-online.target\n[Service]\nExecStartPre=/usr/local/libexec/net-tcp-boot-recovery --wait-dns 40\n")
        code = r'''
br_trusted_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
systemctl() {
    case "$1" in
        list-unit-files) echo 'snell-15479.service enabled enabled';;
        show)
            case "$3" in
                FragmentPath) echo "$BR_ETC/systemd/system/snell-15479.service";;
                DropInPaths) echo "$BR_ETC/systemd/system/snell-15479.service.d/90-net-tcp-boot-recovery.conf";;
            esac;;
    esac
}
br_snell_units
'''
        self.assert_ok(result := self.run_helper(code))
        self.assertEqual(result.stdout, "")
        main.write_text(main.read_text().replace("/opt/unrelated/server", "/usr/local/bin/snell-server -c /etc/snell/snell-15479.conf"))
        self.assert_ok(result := self.run_helper(code))
        self.assertEqual(result.stdout, unit + "\n")
        override = guard.parent / "operator.conf"
        override.write_text("[Service]\nExecStart=\nExecStart=/opt/unrelated/server\n")
        code = code.replace('DropInPaths) echo "$BR_ETC/systemd/system/snell-15479.service.d/90-net-tcp-boot-recovery.conf"', 'DropInPaths) echo "$BR_ETC/systemd/system/snell-15479.service.d/90-net-tcp-boot-recovery.conf $BR_ETC/systemd/system/snell-15479.service.d/operator.conf"')
        self.assert_ok(result := self.run_helper(code))
        self.assertEqual(result.stdout, "")

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

    def test_watch_accepts_only_exact_current_dns_wrapper_and_unit(self):
        wrapper = self.root / "usr/local/bin/dns-purify-apply.sh"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text(subprocess.check_output(["bash", "-c", BLOCK + "\nboot_recovery_emit_dns_apply 8.8.8.8 1.1.1.1"], text=True))
        unit = self.etc / "systemd/system/dns-purify-persist.service"
        unit.parent.mkdir(parents=True)
        unit.write_text(subprocess.check_output(["bash", "-c", BLOCK + "\nboot_recovery_emit_dns_service"], text=True))
        code = r'''
br_trusted_file() { [ -f "$1" ]; }
sha256sum() { python3 - "$1" <<'DIGEST'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(), sys.argv[1])
DIGEST
}
systemctl() {
    case "$3" in
        FragmentPath) echo "$BR_ETC/systemd/system/dns-purify-persist.service";;
        DropInPaths) return 0;;
    esac
}
br_dns_runtime_owned
'''
        self.assert_ok(self.run_helper(code))
        wrapper.write_text(wrapper.read_text() + "# operator changed this wrapper\n")
        self.assertNotEqual(self.run_helper(code).returncode, 0)

    def test_watch_never_restarts_a_modified_marked_dns_wrapper(self):
        wrapper = self.root / "usr/local/bin/dns-purify-apply.sh"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("#!/bin/bash\n# NET_TCP_BOOT_RECOVERY_V1\nexec /opt/operator/dns-maintenance\n")
        unit = self.etc / "systemd/system/dns-purify-persist.service"
        unit.parent.mkdir(parents=True)
        unit.write_text(subprocess.check_output(["bash", "-c", BLOCK + "\nboot_recovery_emit_dns_service"], text=True))
        result = self.run_helper(r'''
br_trusted_file() { [ -f "$1" ]; }
br_wait_dns() { return 1; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$CALLS"; return 0; }
br_watch
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("try-restart", self.calls_text())

    def test_external_dns_failure_does_not_restart_snell(self):
        code = self.watch_code().replace("br_wait_dns() { return 0; }", "br_wait_dns() { return 1; }")
        self.assertNotEqual(self.run_helper(code).returncode, 0)
        self.assertNotIn("snell-15479.service", self.calls_text())

    def test_patch_enumeration_does_not_start_or_enable_stopped_services(self):
        code = r'''
systemctl() {
    if [ "$1" = is-enabled ]; then echo enabled; return 0; fi
    [ "$1" = list-unit-files ] || { echo forbidden >> "$CALLS"; return 99; }
    printf 'snell-15479.service enabled enabled\nsnell-15480.service disabled enabled\nxray.service enabled enabled\nxray@.service disabled enabled\n'
}
boot_recovery_project_units() { printf '%s\n' snell-15479.service xray.service; }
boot_recovery_patch_unit() { printf 'patched %s\n' "$1" >> "$CALLS"; }
boot_recovery_patch_enabled_units
'''
        self.assert_ok(self.run_block(code))
        self.assertEqual(self.calls_text(), "patched snell-15479.service\npatched xray.service\n")

    def test_dns_patch_does_not_claim_unowned_same_name_services(self):
        result = self.run_block(r'''
systemctl() { printf 'xray.service enabled\n'; }
boot_recovery_project_units() { :; }
boot_recovery_patch_unit() { echo PATCHED >> "$CALLS"; }
boot_recovery_patch_enabled_units
''')
        self.assert_ok(result)
        self.assertEqual(self.calls_text(), "")

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
        result = subprocess.run(["bash", "-c", block + '\nboot_recovery_trusted_file() { [ -f "$1" ] && [ ! -L "$1" ]; }\nboot_recovery_write_dns_service 9.9.9.9 149.112.112.112' ],
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
        result = subprocess.run(["bash", "-c", block + '\nboot_recovery_trusted_file() { [ -f "$1" ] && [ ! -L "$1" ]; }\nboot_recovery_write_dns_service 9.9.9.9 149.112.112.112' ],
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


class AutomaticEntryTests(unittest.TestCase):
    """Run real migration orchestration in fixture paths, with fake systemd only."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "run").mkdir()
        (self.root / "home").mkdir()
        (self.root / "usr/local").mkdir(parents=True)
        self.calls = self.root / "calls"
        self.env = dict(os.environ, TEST_ROOT=str(self.root), CALLS=str(self.calls), HOME=str(self.root / "home"))

    def mapped(self, value):
        return re.sub(r"(?<![\w/])/(?:usr|lib|etc|var|run)(?=/)", lambda m: str(self.root) + m[0], value)

    def write(self, name, content):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.mapped(content))
        return path

    def snell(self, port=15479, v6=False):
        name = f"snellv6-{port}.service" if v6 else f"snell-{port}.service"
        label = "Snell V6" if v6 else "Snell"
        binary = "snell-server-v6" if v6 else "snell-server"
        directory = "snell-v6" if v6 else "snell"
        self.write("/etc/systemd/system/" + name,
                   f"[Unit]\nDescription={label} Proxy Service (Port{port})\n[Service]\n"
                   f"ExecStart=/usr/local/bin/{binary} -c /etc/{directory}/snell-{port}.conf\n")
        return name

    def harness(self):
        return self.mapped(BLOCK) + r'''
# Fixture files represent root-owned production files; permission hardening itself
# is separately exercised by the root Linux filesystem/uninstall tests.
boot_recovery_trusted_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
boot_recovery_path_metadata() {
    python3 - "$1" <<'FIXTURE_METADATA'
import os, stat, sys
path = sys.argv[1]
owner = 65534 if path == os.environ.get("UNTRUSTED_DIR", "") else 0
print(owner, format(stat.S_IMODE(os.stat(path).st_mode), "o"))
FIXTURE_METADATA
}
boot_recovery_emit_helper() {
cat <<'FIXTURE_HELPER'
#!/bin/bash
# NET_TCP_BOOT_RECOVERY_V1
printf 'helper %s\n' "$*" >> "$CALLS"
case "$1" in
    --migrate-resolved)
        [ "${HELPER_FAIL:-0}" = 0 ] || exit 1
        rm -f "$TEST_ROOT/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf";;
    --check-current-ipv6) exit "${IPV6_RC:-0}";;
    *) exit 98;;
esac
FIXTURE_HELPER
}
flock() { return 0; }
# Linux helper dependencies are modeled here; absence is tested explicitly.
ss() { return 0; }
getent() { return 0; }
timeout() { shift; "$@"; }
systemctl() {
    if [ "$1" = show ]; then
        case "$3" in
            FragmentPath) [ ! -f "$TEST_ROOT/etc/systemd/system/$5" ] || echo "$TEST_ROOT/etc/systemd/system/$5";;
            DropInPaths)
                [ -z "${CACHED_GUARD_UNIT:-}" ] || echo "$TEST_ROOT/etc/systemd/system/${CACHED_GUARD_UNIT}.d/90-net-tcp-boot-recovery.conf"
                return 0;;
        esac
        return 0
    fi
    printf 'systemctl %s\n' "$*" >> "$CALLS"
    case "$1" in
        is-enabled)
            [ "$2" = net-tcp-boot-watch.timer ] || return 99
            [ -f "$TEST_ROOT/timer-enabled" ] && { echo enabled; return 0; }
            echo disabled; return 1;;
        is-active)
            [ "$3" = net-tcp-boot-watch.timer ] || return 99
            [ -f "$TEST_ROOT/timer-active" ];;
        enable)
            [ "$*" = 'enable --now net-tcp-boot-watch.timer' ] || return 99
            touch "$TEST_ROOT/timer-enabled" "$TEST_ROOT/timer-active";;
        daemon-reload)
            if [ "${FAIL_RELOAD_ONCE:-0}" = 1 ] && [ ! -f "$TEST_ROOT/reload-failed" ]; then
                touch "$TEST_ROOT/reload-failed"; return 1
            fi
            return 0;;
        *) return 99;;
    esac
}
info() { :; }
ensure_xray_dependencies() { return 0; }
success() { echo "success $*" >> "$CALLS"; }
error() { echo "error $*" >> "$CALLS"; }
'''

    def run_code(self, code, *, extra=None):
        env = dict(self.env, **(extra or {}))
        return subprocess.run(["bash", "-c", self.harness() + "\n" + code], env=env,
                              text=True, capture_output=True, timeout=10)

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def calls_text(self):
        return self.calls.read_text() if self.calls.exists() else ""

    def guard(self, unit):
        return self.root / ("etc/systemd/system/" + unit + ".d/90-net-tcp-boot-recovery.conf")

    def test_empty_and_unowned_xray_menu_do_not_create_recovery_assets(self):
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertFalse((self.root / "usr/local/libexec").exists())
        self.write("/etc/systemd/system/xray.service",
                   "[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertFalse(self.guard("xray.service").exists())
        self.assertEqual(self.calls_text(), "")

    def test_owned_snell_v5_v6_menu_migrates_without_starting_business(self):
        v5, v6 = self.snell(), self.snell(15480, True)
        self.write("/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf", BLOCK.split("cat <<'LEGACY_DBUS'\n", 1)[1].split("\nLEGACY_DBUS", 1)[0] + "\n")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertTrue(self.guard(v5).exists())
        self.assertTrue(self.guard(v6).exists())
        self.assertFalse((self.root / "etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf").exists())
        self.assertNotRegex(self.calls_text(), r"systemctl (?:start|stop|restart|try-restart|disable) ")
        self.assertNotIn("enable --now " + v5, self.calls_text())

    def test_repeated_menu_is_quiet_but_missing_guard_and_new_instance_repair(self):
        unit = self.snell()
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        guard = self.guard(unit)
        before = guard.stat().st_mtime_ns
        self.calls.write_text("")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertEqual(guard.stat().st_mtime_ns, before)
        self.assertEqual(self.calls_text().count("daemon-reload"), 1)
        self.assertNotIn("enable --now", self.calls_text())
        guard.unlink()
        other = self.snell(15481)
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertTrue(guard.exists())
        self.assertTrue(self.guard(other).exists())
        self.assertEqual(self.calls_text().count("daemon-reload"), 2)

    def test_reload_failure_is_retried_when_files_are_already_complete(self):
        unit = self.snell()
        first = self.run_code("boot_recovery_migrate auto", extra={"FAIL_RELOAD_ONCE": "1"})
        self.assertNotEqual(first.returncode, 0)
        before = self.guard(unit).stat().st_mtime_ns
        self.assert_ok(self.run_code("boot_recovery_migrate auto", extra={"FAIL_RELOAD_ONCE": "1"}))
        self.assertEqual(self.guard(unit).stat().st_mtime_ns, before)
        self.assertEqual(self.calls_text().count("daemon-reload"), 2)
        self.assertTrue((self.root / "timer-active").exists())

    def test_deleted_guard_is_repaired_despite_systemd_cached_dropin_path(self):
        unit = self.snell()
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.guard(unit).unlink()
        self.assert_ok(self.run_code("boot_recovery_migrate auto", extra={"CACHED_GUARD_UNIT": unit}))
        self.assertTrue(self.guard(unit).is_file())
        # Missing cached paths belonging to a different service are not ours
        # to recreate or ignore, and dangling guard links remain protected.
        self.guard(unit).unlink()
        self.assert_ok(self.run_code("boot_recovery_migrate auto", extra={"CACHED_GUARD_UNIT": "snell-15480.service"}))
        self.assertFalse(self.guard(unit).exists())
        self.guard(unit).symlink_to(self.root / "operator-guard-missing")
        self.assertNotEqual(self.run_code("boot_recovery_migrate install " + unit, extra={"CACHED_GUARD_UNIT": unit}).returncode, 0)
        self.assertTrue(self.guard(unit).is_symlink())

    def test_deleted_helper_is_recreated_despite_previously_complete_migration(self):
        self.snell()
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        helper = self.root / "usr/local/libexec/net-tcp-boot-recovery"
        helper.unlink()
        self.calls.write_text("")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertTrue(helper.is_file())
        self.assertIn("daemon-reload", self.calls_text())

    def test_modified_project_guard_is_preserved_and_auto_skips_it(self):
        unit = self.snell()
        path = self.guard(unit)
        path.parent.mkdir(parents=True)
        original = "# NET_TCP_BOOT_RECOVERY_V1\n[Service]\nExecStartPre=/operator/custom\n"
        path.write_text(original)
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertEqual(path.read_text(), original)
        self.assertNotIn("enable --now", self.calls_text())

    def test_same_marker_does_not_authorize_overwriting_custom_watch_timer(self):
        self.snell()
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        timer = self.root / "etc/systemd/system/net-tcp-boot-watch.timer"
        original = timer.read_text() + "# operator changes\n"
        timer.write_text(original)
        self.calls.write_text("")
        self.assertNotEqual(self.run_code("boot_recovery_migrate auto").returncode, 0)
        self.assertEqual(timer.read_text(), original)
        self.assertEqual(self.calls_text(), "")

    def test_unrelated_ipv6_conflict_does_not_gate_recovery(self):
        unit = self.snell()
        result = self.run_code("boot_recovery_migrate auto", extra={"IPV6_RC": "1"})
        self.assert_ok(result)
        self.assertTrue(self.guard(unit).exists())
        self.assertNotIn("--check-current-ipv6", self.calls_text())
        self.assertNotRegex(self.calls_text(), r"systemctl (?:restart|start|stop) ")

    def test_migration_lock_descriptor_is_released_before_next_call(self):
        self.snell()
        self.assert_ok(self.run_code(r'''
boot_recovery_migrate auto || exit
if (: <&209) 2>/dev/null; then exit 90; fi
boot_recovery_migrate auto
'''))

    def test_xray_install_record_allows_menu_but_unknown_record_does_not(self):
        self.write("/etc/systemd/system/xray.service",
                   "[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n")
        record = self.write("/var/lib/net-tcp-tune/xray-install.json", '{"version": 1, "paths": ["/usr/local/bin/xray"]}')
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertTrue(self.guard("xray.service").exists())
        self.guard("xray.service").unlink()
        record.write_text('{"version": 99, "paths": []}')
        self.calls.write_text("")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertFalse(self.guard("xray.service").exists())
        self.assertEqual(self.calls_text(), "")

    def test_old_xray_exact_project_override_is_recognized_without_install_record(self):
        self.write("/etc/systemd/system/xray.service",
                   "[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n")
        override = self.write("/etc/systemd/system/xray.service.d/override.conf",
                              "[Service]\nRestart=always\nRestartSec=5\nKillMode=mixed\nKillSignal=SIGTERM\n"
                              "TimeoutStopSec=5s\nOOMScoreAdjust=-500\n\n[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=10\n")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertTrue(self.guard("xray.service").exists())
        self.guard("xray.service").unlink()
        override.write_text(override.read_text() + "# operator changes\n")
        self.calls.write_text("")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertFalse(self.guard("xray.service").exists())
        self.assertEqual(self.calls_text(), "")

    def test_legacy_dns_only_menu_migrates_without_enabling_disabled_dns_service(self):
        head = BLOCK.split("cat <<'LEGACY_DNS_HEAD'\n", 1)[1].split("\nLEGACY_DNS_HEAD", 1)[0]
        body = BLOCK.split("cat <<'LEGACY_DNS_BODY'\n", 1)[1].split("\nLEGACY_DNS_BODY", 1)[0]
        apply = self.write("/usr/local/bin/dns-purify-apply.sh",
                           head + '\nDNS_PRIMARY="8.8.8.8"\nDNS_SECONDARY="1.1.1.1"\n' + body + "\n")
        unit = BLOCK.split("cat <<'LEGACY_DNS_UNIT'\n", 1)[1].split("\nLEGACY_DNS_UNIT", 1)[0]
        service = self.write("/etc/systemd/system/dns-purify-persist.service", unit + "\n")
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertIn("NET_TCP_BOOT_RECOVERY_V1", apply.read_text())
        self.assertIn("Restart=on-failure", service.read_text())
        self.assertNotIn("enable dns-purify-persist", self.calls_text())
        self.assertNotIn("restart dns-purify-persist", self.calls_text())
        before = apply.stat().st_mtime_ns
        self.assert_ok(self.run_code("boot_recovery_migrate auto"))
        self.assertEqual(apply.stat().st_mtime_ns, before)

    def test_modified_managed_dns_wrapper_is_preserved_without_migration(self):
        apply = self.write("/usr/local/bin/dns-purify-apply.sh",
                           '#!/bin/bash\n# NET_TCP_BOOT_RECOVERY_V1\nDNS_PRIMARY="8.8.8.8"\n'
                           'DNS_SECONDARY="1.1.1.1"\n/operator/custom\n')
        before = apply.read_text()
        self.assertNotEqual(self.run_code("boot_recovery_migrate auto").returncode, 0)
        self.assertEqual(apply.read_text(), before)
        self.assertEqual(self.calls_text(), "")

    def test_explicit_target_ignores_other_guard_dns_and_ipv6_conflicts(self):
        unit = self.snell()
        path = self.guard(unit)
        path.parent.mkdir(parents=True)
        path.write_text("[Service]\nExecStartPre=/operator/custom\n")
        self.write("/usr/local/bin/dns-purify-apply.sh", "# NET_TCP_BOOT_RECOVERY_V1\ncustom\n")
        result = self.run_code("boot_recovery_migrate install xray.service", extra={"IPV6_RC": "1"})
        self.assert_ok(result)
        self.assertTrue(self.guard("xray.service").exists())
        self.assertNotIn("--check-current-ipv6", self.calls_text())
        self.assertNotIn("--migrate-resolved", self.calls_text())

    def test_missing_guard_dependencies_leave_all_assets_unchanged(self):
        self.snell()
        result = self.run_code(r'''
command() {
    if [ "${1:-}" = -v ] && [ "${2:-}" = timeout ]; then return 1; fi
    builtin command "$@"
}
boot_recovery_migrate auto
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "usr/local/libexec").exists())
        self.assertEqual(self.calls_text(), "")

    def test_custom_guard_is_preflighted_before_shared_assets_write(self):
        unit = self.snell()
        path = self.guard(unit)
        path.parent.mkdir(parents=True)
        path.write_text("[Service]\nExecStartPre=/operator/custom\n")
        self.assertNotEqual(self.run_code("boot_recovery_migrate install " + unit).returncode, 0)
        self.assertFalse((self.root / "usr/local/libexec").exists())
        self.assertEqual(self.calls_text(), "")

    def test_dns_rollback_restores_existing_helper_and_new_timer_independently(self):
        helper = self.write("/usr/local/libexec/net-tcp-boot-recovery", "old helper bytes\n")
        helper.chmod(0o751)
        script = r'''
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$CALLS"
    case "$1" in
        is-enabled) echo disabled; return 1;;
        is-active) [ -f "$TEST_ROOT/timer-running" ];;
        stop) rm -f "$TEST_ROOT/timer-running";;
        disable|daemon-reload) return 0;;
        *) return 99;;
    esac
}
boot_recovery_snapshot_dns_assets "$TEST_ROOT/pre_state" || exit
printf 'new helper bytes\n' > "$TEST_ROOT/usr/local/libexec/net-tcp-boot-recovery"
chmod 755 "$TEST_ROOT/usr/local/libexec/net-tcp-boot-recovery"
mkdir -p "$TEST_ROOT/etc/systemd/system"
printf 'new timer\n' > "$TEST_ROOT/etc/systemd/system/net-tcp-boot-watch.timer"
printf 'new service\n' > "$TEST_ROOT/etc/systemd/system/net-tcp-boot-watch.service"
touch "$TEST_ROOT/timer-running"
export -f systemctl flock
bash "$TEST_ROOT/pre_state/boot-recovery-restore.sh"
'''
        self.assert_ok(self.run_code(script))
        self.assertEqual(helper.read_text(), "old helper bytes\n")
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o751)
        self.assertFalse((self.root / "etc/systemd/system/net-tcp-boot-watch.timer").exists())
        self.assertFalse((self.root / "etc/systemd/system/net-tcp-boot-watch.service").exists())
        self.assertIn("systemctl stop net-tcp-boot-watch.timer", self.calls_text())
        self.assertIn("systemctl disable net-tcp-boot-watch.timer", self.calls_text())
        self.assertNotRegex(self.calls_text(), r"systemctl (?:restart|try-restart) ")

    def test_late_proxy_consumer_keeps_shared_helper_on_standalone_dns_rollback(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                helper = self.root / "usr/local/libexec/net-tcp-boot-recovery"
                helper.parent.mkdir(parents=True, exist_ok=True)
                if existing:
                    helper.write_text("old helper only supports wait-dns\n")
                elif helper.exists():
                    helper.unlink()
                guard = self.root / "etc/systemd/system/xray.service.d/90-net-tcp-boot-recovery.conf"
                if guard.exists():
                    guard.unlink()
                script = r'''
systemctl() {
    case "$1" in
        is-enabled) echo disabled; return 1;;
        is-active) return 1;;
        disable|daemon-reload) return 0;;
        *) return 99;;
    esac
}
boot_recovery_snapshot_dns_assets "$TEST_ROOT/pre_state" || exit
printf 'current helper supporting prepare-app-dns\n' > "$TEST_ROOT/usr/local/libexec/net-tcp-boot-recovery"
mkdir -p "$TEST_ROOT/etc/systemd/system/xray.service.d"
printf 'later proxy watch timer\n' > "$TEST_ROOT/etc/systemd/system/net-tcp-boot-watch.timer"
printf 'later proxy watch service\n' > "$TEST_ROOT/etc/systemd/system/net-tcp-boot-watch.service"
printf 'ExecStartPre=%s --prepare-app-dns 40\n' "$TEST_ROOT/usr/local/libexec/net-tcp-boot-recovery" > "$TEST_ROOT/etc/systemd/system/xray.service.d/90-net-tcp-boot-recovery.conf"
export -f systemctl flock
bash "$TEST_ROOT/pre_state/boot-recovery-restore.sh"
'''
                result = self.run_code(script)
                self.assert_ok(result)
                self.assertEqual(helper.read_text(), "current helper supporting prepare-app-dns\n")
                self.assertTrue(guard.is_file())
                self.assertEqual((self.root / "etc/systemd/system/net-tcp-boot-watch.timer").read_text(), "later proxy watch timer\n")
                self.assertIn("保留当前shared helper", result.stderr)

    def test_dns_rollback_preserves_preexisting_enabled_active_timer(self):
        helper = self.write("/usr/local/libexec/net-tcp-boot-recovery", "old shared helper\n")
        timer = self.write("/etc/systemd/system/net-tcp-boot-watch.timer", "old timer\n")
        service = self.write("/etc/systemd/system/net-tcp-boot-watch.service", "old service\n")
        script = r'''
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$CALLS"
    case "$1" in
        is-enabled) echo enabled;;
        is-active|enable|start|daemon-reload) return 0;;
        *) return 99;;
    esac
}
boot_recovery_snapshot_dns_assets "$TEST_ROOT/pre_state" || exit
printf 'changed\n' > "$TEST_ROOT/etc/systemd/system/net-tcp-boot-watch.timer"
export -f systemctl flock
bash "$TEST_ROOT/pre_state/boot-recovery-restore.sh"
'''
        self.assert_ok(self.run_code(script))
        self.assertEqual(timer.read_text(), "old timer\n")
        self.assertEqual(service.read_text(), "old service\n")
        self.assertEqual(helper.read_text(), "old shared helper\n")
        self.assertNotIn("systemctl disable", self.calls_text())
        self.assertNotIn("systemctl stop", self.calls_text())

    def test_effective_runtime_overrides_are_preserved_without_guard_injection(self):
        for kind in ("snell", "xray"):
            unit = self.snell() if kind == "snell" else "xray.service"
            if kind == "xray":
                self.write("/etc/systemd/system/xray.service", "[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n")
                self.write("/var/lib/net-tcp-tune/xray-install.json", '{"version":1,"paths":["/usr/local/bin/xray"]}')
            for directive in ("RootDirectory=/srv/chroot", "RootImage=/srv/root.img", "InaccessiblePaths=/usr/local/libexec", "SystemCallFilter=@system-service", "ExecStartPre=/opt/operator/check", "ExecStart=/opt/operator/server"):
                with self.subTest(kind=kind, directive=directive):
                    override = self.write("/etc/systemd/system/" + unit + ".d/operator.conf", "[Service]\n" + directive + "\n")
                    self.assert_ok(self.run_code("boot_recovery_migrate auto"))
                    self.assertFalse(self.guard(unit).exists())
                    self.assertNotEqual(self.run_code("boot_recovery_migrate install " + unit).returncode, 0)
                    self.assertFalse((self.root / "usr/local/libexec/net-tcp-boot-recovery").exists())
                    self.assertEqual(override.read_text(), self.mapped("[Service]\n" + directive + "\n"))
            # Remove this component before the next kind to keep the no-assets check strict.
            override.unlink()
            (self.root / ("etc/systemd/system/" + unit)).unlink()

    def test_fresh_units_check_global_template_and_prefix_overrides(self):
        for directory, unit in (("service.d", "xray.service"), ("xray@.service.d", "xray@one.service"), ("snell-.service.d", "snell-15479.service")):
            with self.subTest(directory=directory):
                custom = self.write("/etc/systemd/system/" + directory + "/operator.conf", "[Service]\nRootDirectory=/srv/chroot\n")
                self.assertNotEqual(self.run_code("boot_recovery_migrate install " + unit).returncode, 0)
                self.assertFalse(self.guard(unit).exists())
                self.assertFalse((self.root / "usr/local/libexec/net-tcp-boot-recovery").exists())
                custom.unlink()
        custom = self.write("/etc/systemd/system/service.d/cpu.conf", "[Service]\nCPUQuota=50%\n")
        self.assert_ok(self.run_code("boot_recovery_migrate install xray.service"))
        self.assertTrue(self.guard("xray.service").exists())
        self.assertEqual(custom.read_text(), "[Service]\nCPUQuota=50%\n")

    def test_cpu_resource_dropin_does_not_block_xray_guard(self):
        self.write("/etc/systemd/system/xray.service", "[Service]\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n")
        custom = self.write("/etc/systemd/system/xray.service.d/cpu.conf", "[Service]\nCPUQuota=50%\nMemoryMax=512M\n")
        before = custom.read_bytes()
        self.assert_ok(self.run_code("boot_recovery_migrate install xray.service"))
        self.assertTrue(self.guard("xray.service").exists())
        self.assertEqual(custom.read_bytes(), before)

    def test_custom_resolved_dropin_is_preflighted_before_asset_writes(self):
        self.snell()
        custom = self.write("/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf", "[Service]\nEnvironment=OPERATOR=1\n")
        self.assertNotEqual(self.run_code("boot_recovery_migrate auto").returncode, 0)
        self.assertFalse((self.root / "usr/local/libexec").exists())
        self.assertEqual(custom.read_text(), "[Service]\nEnvironment=OPERATOR=1\n")

    def test_explicit_unenabled_install_target_is_protected(self):
        self.assert_ok(self.run_code("boot_recovery_migrate install xray.service"))
        self.assertTrue(self.guard("xray.service").exists())
        self.assertNotIn("enable --now xray", self.calls_text())
        self.assertNotIn("start xray", self.calls_text())

    def test_existing_private_libexec_gets_search_but_no_new_read_permissions(self):
        directory = self.root / "usr/local/libexec"
        directory.mkdir(mode=0o700)
        for original, expected in ((0o700, 0o711), (0o750, 0o751), (0o701, 0o711)):
            with self.subTest(original=original):
                directory.chmod(original)
                self.assert_ok(self.run_code("boot_recovery_migrate install xray.service"))
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), expected)
        helper = directory / "net-tcp-boot-recovery"
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o755)

    def test_untrusted_or_world_writable_exec_directory_is_not_changed(self):
        directory = self.root / "usr/local/libexec"
        directory.mkdir(mode=0o700)
        for mode, extra in ((0o700, {"UNTRUSTED_DIR": str(directory)}), (0o777, {}), (0o770, {})):
            with self.subTest(mode=mode, extra=extra):
                directory.chmod(mode)
                self.assertNotEqual(self.run_code("boot_recovery_migrate install xray.service", extra=extra).returncode, 0)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), mode)
                self.assertFalse((directory / "net-tcp-boot-recovery").exists())

    def test_symlink_exec_directory_is_not_followed(self):
        directory = self.root / "usr/local/libexec"
        other = self.root / "other-tools"
        other.mkdir()
        directory.symlink_to(other, target_is_directory=True)
        self.assertNotEqual(self.run_code("boot_recovery_migrate install xray.service").returncode, 0)
        self.assertEqual(list(other.iterdir()), [])

    def test_restricted_exec_ancestor_is_reported_without_permission_changes(self):
        ancestor = self.root / "usr/local"
        ancestor.chmod(0o700)
        result = self.run_code("boot_recovery_migrate install xray.service")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE(ancestor.stat().st_mode), 0o700)
        self.assertFalse((ancestor / "libexec/net-tcp-boot-recovery").exists())

    def dependency_fixture(self):
        binary = self.write("/usr/bin/python3", "#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        return self.mapped(function("ensure_xray_dependencies")) + r'''
require_no_xray_transaction() { return 0; }
command() {
    if [ "${1:-}" = -v ]; then
        case "$2" in
            jq|curl|timeout|getent|openssl)
                case " ${EXTRA_MISSING_TOOLS:-} " in
                    *" $2 "*) [ -f "$TEST_ROOT/deps-installed" ]; return $?;;
                esac
                return 0;;
            ss) [ -f "$TEST_ROOT/ss-installed" ]; return $?;;
        esac
    fi
    builtin command "$@"
}
apt-get() {
    echo "apt $*" >> "$CALLS"
    [ "${APT_FAIL:-0}" = 0 ] || return 1
    if [ "$1" = install ] && [ "${LEAVE_SS_MISSING:-0}" = 0 ]; then touch "$TEST_ROOT/ss-installed" "$TEST_ROOT/deps-installed"; fi
    return 0
}
ensure_xray_dependencies
'''

    def test_xray_prepares_missing_dns_socket_probe_before_installing_guard(self):
        self.assert_ok(self.run_code(self.dependency_fixture()))
        self.assertIn("iproute2", self.calls_text())
        self.assertTrue((self.root / "ss-installed").exists())

    def test_xray_dependency_install_failure_is_not_reported_as_ready(self):
        self.assertNotEqual(self.run_code(self.dependency_fixture(), extra={"APT_FAIL": "1"}).returncode, 0)

    def test_xray_dependency_commands_are_verified_after_package_success(self):
        result = self.run_code(self.dependency_fixture(), extra={"LEAVE_SS_MISSING": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ss", self.calls_text())

    def test_xray_ready_dependencies_do_not_run_package_manager(self):
        (self.root / "ss-installed").touch()
        self.assert_ok(self.run_code(self.dependency_fixture()))
        self.assertEqual(self.calls_text(), "")

    def test_xray_installs_dns_and_key_generation_packages_when_missing(self):
        self.assert_ok(self.run_code(self.dependency_fixture(), extra={"EXTRA_MISSING_TOOLS": "timeout getent openssl"}))
        packages = self.calls_text()
        for package in ("iproute2", "coreutils", "libc-bin", "openssl"):
            self.assertIn(package, packages)

    def test_snell_install_prepares_dns_guard_dependencies_on_both_package_families(self):
        code = self.mapped(function("install_required_packages_snell")) + r'''
get_system_type_snell() { echo "$FIXTURE_DISTRO"; }
apt() { echo "apt $*" >> "$CALLS"; }
yum() { echo "yum $*" >> "$CALLS"; }
install_required_packages_snell
'''
        for distro, package in (("debian", "iproute2"), ("centos", "iproute")):
            with self.subTest(distro=distro):
                self.calls.write_text("")
                self.assert_ok(self.run_code(code, extra={"FIXTURE_DISTRO": distro}))
                self.assertIn(package, self.calls_text())
                self.assertIn("coreutils", self.calls_text())

    def test_real_child_bash_receives_complete_recovery_function_closure(self):
        self.assert_ok(self.run_code(r'''
boot_recovery_export_functions
export -f systemctl flock timeout getent ss
bash -euc 'boot_recovery_migrate install xray.service'
'''))
        self.assertTrue(self.guard("xray.service").exists())

    def test_main_migrates_before_loading_user_config(self):
        (self.root / "home/.net-tcp-tune.conf").write_text('echo config >> "$CALLS"\n')
        code = function("parse_args") + "\n" + function("main") + r'''
check_root() { :; }
boot_recovery_migrate() { echo migrate >> "$CALLS"; }
show_main_menu() { echo menu >> "$CALLS"; exit 0; }
main
'''
        self.assert_ok(self.run_code(self.mapped(code)))
        self.assertEqual(self.calls_text(), "migrate\nconfig\nmenu\n")

    def test_help_version_and_readonly_uninstall_skip_automatic_migration(self):
        code = function("parse_args") + "\n" + function("main") + r'''
check_root() { :; }
boot_recovery_migrate() { echo forbidden >> "$CALLS"; return 90; }
run_xray_safe_uninstall() { echo "uninstall $*" >> "$CALLS"; }
show_help() { :; }
log_debug() { :; }
SCRIPT_VERSION=fixture
read -r -a entry_args <<< "$ENTRY_ARG"
main "${entry_args[@]}"
'''
        for arg in ("-h", "-v", "--xray-uninstall-check", "--debug --xray-uninstall-check", "-q --xray-uninstall-check"):
            with self.subTest(arg=arg):
                self.assert_ok(self.run_code(self.mapped(code), extra={"ENTRY_ARG": arg}))
        self.assertEqual(self.calls_text(), "uninstall --check\n" * 3)

    def test_snell_v5_update_stops_before_download_on_recovery_failure(self):
        self.write("/usr/local/bin/snell-server", "fixture")
        code = self.mapped(function("update_snell")) + r'''
snell_acquire_lock() { return 0; }
snell_prepare_recovery_dependencies() { return 0; }
snell_release_lock() { echo release >> "$CALLS"; }
snell_apply_runtime_guards() { echo recovery-failure >> "$CALLS"; return 1; }
wait_for_package_manager_snell() { echo forbidden-download >> "$CALLS"; }
update_snell
'''
        self.assertNotEqual(self.run_code(code).returncode, 0)
        self.assertEqual(self.calls_text(), "recovery-failure\nrelease\n")

    def test_snell_v6_latest_path_migrates_before_version_shortcut(self):
        self.write("/usr/local/bin/snell-server-v6", "fixture")
        self.write("/etc/snell-v6/.binary-version", "6.0.0")
        code = function("snellv6_update_and_repair") + r'''
SNELLV6_BIN="$TEST_ROOT/usr/local/bin/snell-server-v6"
SNELLV6_VERSION_FILE="$TEST_ROOT/etc/snell-v6/.binary-version"
SNELL_V6_DEFAULT_VERSION=6.0.0
snellv6_acquire_lock() { return 0; }
snell_prepare_recovery_dependencies() { return 0; }
wait_for_package_manager_snell() { :; }
install_required_packages_snell() { return 0; }
snellv6_release_lock() { echo release >> "$CALLS"; }
snellv6_list_units() { echo snellv6-15480.service; }
snellv6_apply_runtime_guards() { echo recovery-failure >> "$CALLS"; return 1; }
snellv6_restart_units_with_healthcheck() { echo forbidden-restart >> "$CALLS"; }
snellv6_update_and_repair
'''
        self.assertNotEqual(self.run_code(code).returncode, 0)
        self.assertEqual(self.calls_text(), "recovery-failure\nrelease\n")

    def test_snell_v6_latest_success_migrates_and_preserves_manual_stop(self):
        unit = self.snell(15480, True)
        self.write("/usr/local/bin/snell-server-v6", "fixture")
        self.write("/etc/snell-v6/.binary-version", "6.0.0")
        code = self.mapped(function("snellv6_apply_runtime_guards")) + "\n" + function("snellv6_update_and_repair") + r'''
SNELLV6_BIN="$TEST_ROOT/usr/local/bin/snell-server-v6"
SNELLV6_VERSION_FILE="$TEST_ROOT/etc/snell-v6/.binary-version"
SNELL_V6_DEFAULT_VERSION=6.0.0
snellv6_acquire_lock() { return 0; }
snell_prepare_recovery_dependencies() { return 0; }
wait_for_package_manager_snell() { :; }
install_required_packages_snell() { return 0; }
snellv6_release_lock() { :; }
snellv6_list_units() { echo snellv6-15480.service; }
snellv6_sync_reserved_ports() { return 0; }
snellv6_current_ports_csv() { echo 15480; }
snellv6_install_daily_restart_cron() { return 0; }
snell_should_restart_unit() { return 1; }
snellv6_restart_units_with_healthcheck() { [ "$#" -eq 0 ] || return 91; echo preserved-manual-stop >> "$CALLS"; }
snellv6_health_check() { return 0; }
snellv6_update_and_repair
'''
        self.assert_ok(self.run_code(code))
        self.assertTrue(self.guard(unit).exists())
        self.assertIn("preserved-manual-stop", self.calls_text())
        self.assertNotIn("systemctl start", self.calls_text())

    def test_xray_core_install_guard_exists_before_official_installer(self):
        code = XRAY_VERSION_POLICY + "\n" + self.mapped(function("run_core_install")) + r'''
execute_official_script() {
    [ -f "$TEST_ROOT/etc/systemd/system/xray.service.d/90-net-tcp-boot-recovery.conf" ] || return 91
    echo "official $*" >> "$CALLS"
}
run_xray_safe_uninstall() { echo record >> "$CALLS"; }
xray_sync_existing_config_owner() { echo fixture-config-sync >> "$CALLS"; }
run_core_install
'''
        self.assert_ok(self.run_code(code))
        self.assertIn("official install --version v26.3.27\n", self.calls_text())
        self.assertNotIn("helper --migrate-resolved", self.calls_text())

    def test_xray_core_install_aborts_before_official_on_migration_failure(self):
        code = self.mapped(function("run_core_install")) + r'''
execute_official_script() { echo forbidden-official >> "$CALLS"; }
run_core_install
'''
        self.write("/usr/local/libexec/net-tcp-boot-recovery", "operator custom helper\n")
        self.assertNotEqual(self.run_code(code).returncode, 0)
        self.assertNotIn("official", self.calls_text())

    def test_xray_already_latest_update_runs_full_migration(self):
        binary = self.write("/usr/local/bin/xray", "#!/bin/sh\necho 'Xray 26.3.27'\n")
        binary.chmod(0o755)
        code = XRAY_VERSION_POLICY + "\n" + function("update_xray") + r'''
xray_binary_path="$TEST_ROOT/usr/local/bin/xray"
curl() { echo '{"tag_name":"v26.3.27"}'; }
jq() { echo v26.3.27; }
run_core_install() { echo forbidden-core-update >> "$CALLS"; return 99; }
restart_xray() { echo forbidden-restart >> "$CALLS"; return 99; }
update_xray
'''
        # 固定版本与 latest 两种策略下的"已是最新"路径都必须先完成迁移。
        for override in ("", "latest"):
            with self.subTest(override=override):
                self.guard("xray.service").unlink(missing_ok=True)
                self.assert_ok(self.run_code(code, extra={"XRAY_VERSION_OVERRIDE": override}))
                self.assertTrue(self.guard("xray.service").exists())
                self.assertNotIn("forbidden", self.calls_text())


if __name__ == "__main__":
    unittest.main()
