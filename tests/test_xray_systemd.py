"""Opt-in real systemd + Snell 5 + Xray integration in a disposable container.

Never run on a VPS. Requires /.dockerenv, /root/xray-uninstall-isolated-container,
XRAY_ISOLATED_SYSTEMD_TEST=1, PID 1 systemd and predownloaded official binaries
at /root/xray-test-assets/{xray,snell-server}. Does not install/download tools.
The Snell probe checks live TCP acceptance, NOT authenticated Snell proxy traffic.
The client-confirmation gate is exercised with test input.
"""
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import subprocess
import threading
import time
import unittest

from test_xray_uninstall import MODULE, UNIT

ENABLED = (os.environ.get("XRAY_ISOLATED_SYSTEMD_TEST") == "1" and os.geteuid() == 0 and
           Path("/.dockerenv").exists() and Path("/root/xray-uninstall-isolated-container").is_file() and
           Path("/proc/1/comm").read_text().strip() == "systemd")
SCRIPT = Path(__file__).resolve().parents[1] / "net-tcp-tune.sh"


def systemctl(*args):
    return subprocess.check_output(["/usr/bin/systemctl", *args], text=True).strip()


def write(name, content, mode=0o644):
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def interactive(flag, answers):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv("/bin/bash", ["bash", str(SCRIPT), flag])
    output = b""
    remaining = list(answers)
    deadline = time.monotonic() + 60
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                output += chunk
            if remaining and remaining[0][0].encode() in output:
                _, response = remaining.pop(0)
                os.write(fd, response.encode() + b"\n")
            done, state = os.waitpid(pid, os.WNOHANG)
            if done:
                status = state
                break
        if status is None:
            done, state = os.waitpid(pid, os.WNOHANG)
            if not done:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                raise AssertionError("interactive test timed out: " + output.decode(errors="replace"))
            status = state
    finally:
        os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


@unittest.skipUnless(ENABLED, "Opt-in disposable systemd container only")
class RealSystemdTests(unittest.TestCase):
    def setUp(self):
        # A fresh disposable image has no units; fixture cleanup tolerates that.
        for action in ("stop", "disable"):
            subprocess.run(["/usr/bin/systemctl", action, "xray.service", "xray@one.service"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for name in MODULE.FIXED:
            path = Path(name)
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        shutil.rmtree(MODULE.STATE, ignore_errors=True)
        self.assets = Path("/root/xray-test-assets")
        Path("/usr/local/bin").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.assets / "xray", "/usr/local/bin/xray")
        os.chmod("/usr/local/bin/xray", 0o755)
        if not Path("/usr/local/bin/snell-server").exists():
            shutil.copyfile(self.assets / "snell-server", "/usr/local/bin/snell-server")
            os.chmod("/usr/local/bin/snell-server", 0o755)
        write("/etc/snell/snell-server.conf", "[snell-server]\nlisten=127.0.0.1:19123\npsk=isolated-test-not-a-real-secret\nipv6=false\n", 0o600)
        write("/etc/systemd/system/snell-19123.service", "[Unit]\nDescription=Isolated Snell\n[Service]\nExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf\n[Install]\nWantedBy=multi-user.target\n")
        write("/etc/systemd/system/xray.service", UNIT)
        write("/etc/systemd/system/xray@.service", UNIT.replace("config.json", "%i.json").replace("RuntimeDirectory=xray\n", "RuntimeDirectory=xray-%i\n"))
        write("/etc/systemd/system/xray.service.d/override.conf", "[Service]\nRestart=always\nRestartSec=5\nKillMode=mixed\nTimeoutStopSec=5s\n")
        config = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": 19080,
                  "protocol": "vless", "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111"}], "decryption": "none"}}],
                  "outbounds": [{"protocol": "freedom"}]}
        write("/usr/local/etc/xray/config.json", json.dumps(config), 0o640)
        os.chown("/usr/local/etc/xray/config.json", 65534, 0)
        write("/usr/local/share/xray/geoip.dat", "isolated geoip")
        write("/usr/local/share/xray/geosite.dat", "isolated geosite")
        write("/var/log/xray/error.log", "isolated log")
        write("/root/xray_subscription_info.txt", "vless://dummy\n", 0o600)
        write("/usr/local/etc/mtu-optimize.conf", "DEFAULT_IFACE=eth0\nORIGINAL_MTU=1500\n")
        systemctl("daemon-reload")
        systemctl("enable", "snell-19123.service", "xray.service")
        systemctl("start", "snell-19123.service", "xray.service")
        # A successful connect confirms each actual server has bound its listener.
        for port in (19123, 19080):
            deadline = time.monotonic() + 5
            while True:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.02)
        self.env = MODULE.Environment()
        self.before = self.env.snell_snapshot()
        self.client_stop = threading.Event()
        self.probe_failures = []
        self.probe_count = 0
        def probe():
            while not self.client_stop.is_set():
                try:
                    socket.create_connection(("127.0.0.1", 19123), timeout=0.5).close()
                    self.probe_count += 1
                except OSError as exc:
                    self.probe_failures.append(str(exc))
                self.client_stop.wait(0.02)
        self.prober = threading.Thread(target=probe)
        self.prober.start()

    def tearDown(self):
        self.client_stop.set()
        self.prober.join(2)
        for path in (Path("/etc/systemd/system/snell-19123.service.d/test.conf"),
                     Path("/etc/systemd/system/xray.service.d/test.conf")):
            if path.exists():
                path.unlink()
        systemctl("daemon-reload")

    def test_shared_logrotate_timer_survives_xray_uninstall(self):
        write("/etc/systemd/system/logrotate@.timer", "[Unit]\nDescription=Run logrotate for %i logs\n[Timer]\nOnCalendar=2099-01-01 00:00:00\nPersistent=false\n[Install]\nWantedBy=timers.target\n")
        write("/etc/systemd/system/logrotate@.service", "[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.d/%i\n")
        write("/etc/logrotate.d/xray", "/var/log/xray/*.log {\n daily\n missingok\n rotate 7\n}\n")
        write("/etc/logrotate.d/snell", "protected test policy")
        systemctl("daemon-reload")
        systemctl("enable", "--now", "logrotate@xray.timer", "logrotate@snell.timer")
        self.before = self.env.snell_snapshot()
        timer = Path("/etc/systemd/system/logrotate@.timer").read_bytes()
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "卸载Xray"), ("请输入 Snell已验证", "Snell已验证")])
        self.assertEqual(rc, 0, output)
        self.assertEqual(Path("/etc/systemd/system/logrotate@.timer").read_bytes(), timer)
        self.assertEqual(systemctl("is-active", "logrotate@snell.timer"), "active")
        self.assertEqual(systemctl("is-enabled", "logrotate@snell.timer"), "enabled")
        self.assertTrue(Path("/etc/logrotate.d/snell").exists())
        self.assert_snell()
        result = subprocess.run(["bash", str(SCRIPT), "--xray-uninstall"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_snell(self):
        self.assertEqual(self.env.snell_snapshot(), self.before)
        self.assertEqual(self.probe_failures, [])
        self.assertGreater(self.probe_count, 0)

    def test_readonly_full_script_preserves_legacy_mtu(self):
        marker = Path("/usr/local/etc/mtu-optimize.conf").read_bytes()
        result = subprocess.run(["bash", str(SCRIPT), "--xray-uninstall-check"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(Path("/usr/local/etc/mtu-optimize.conf").read_bytes(), marker)
        self.assertEqual(systemctl("is-active", "xray.service"), "active")
        self.assert_snell()

    def test_inherited_menu_lock_does_not_deadlock_helper(self):
        result = subprocess.run(["bash", "-c", 'mkdir -p /run/net-tcp-tune-xray; chmod 700 /run/net-tcp-tune-xray; '
                                 'exec 9<>/run/net-tcp-tune-xray/lock; flock -n 9; bash "$1" --xray-uninstall-check',
                                 "test", str(SCRIPT)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_snell()

    def test_cancel_initial_confirmation_leaves_service_active(self):
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "no")])
        self.assertNotEqual(rc, 0, output)
        self.assertEqual(systemctl("is-active", "xray.service"), "active")
        self.assert_snell()

    def test_cancel_client_gate_restores_xray(self):
        original = Path("/usr/local/etc/xray/config.json").read_bytes()
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "卸载Xray"), ("请输入 Snell已验证", "")])
        self.assertNotEqual(rc, 0, output)
        self.assertEqual(Path("/usr/local/etc/xray/config.json").read_bytes(), original)
        self.assertEqual(systemctl("is-active", "xray.service"), "active")
        self.assert_snell()

    def test_complete_and_repeat(self):
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "卸载Xray"), ("请输入 Snell已验证", "Snell已验证")])
        self.assertEqual(rc, 0, output)
        self.assertFalse(Path("/usr/local/bin/xray").exists())
        self.assertFalse(Path("/usr/local/etc/xray").exists())
        self.assert_snell()
        result = subprocess.run(["bash", str(SCRIPT), "--xray-uninstall"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_binary_with_running_process(self):
        Path("/usr/local/bin/xray").unlink()
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "卸载Xray"), ("请输入 Snell已验证", "Snell已验证")])
        self.assertEqual(rc, 0, output)
        self.assertFalse(Path("/usr/local/etc/xray").exists())
        self.assert_snell()

    def test_main_and_instance_both_removed(self):
        config = json.loads(Path("/usr/local/etc/xray/config.json").read_text())
        config["inbounds"][0]["port"] = 19081
        write("/usr/local/etc/xray/one.json", json.dumps(config), 0o640)
        os.chown("/usr/local/etc/xray/one.json", 65534, 0)
        systemctl("enable", "xray@one.service")
        systemctl("start", "xray@one.service")
        rc, output = interactive("--xray-uninstall", [("请输入 卸载Xray", "卸载Xray"), ("请输入 Snell已验证", "Snell已验证")])
        self.assertEqual(rc, 0, output)
        self.assertFalse(any(Path(exe).name == "xray" for _, exe, _ in self.env.processes()))
        self.assert_snell()

    def test_snell_partof_relationship_blocks_stop(self):
        write("/etc/systemd/system/snell-19123.service.d/test.conf", "[Unit]\nPartOf=xray.service\n")
        systemctl("daemon-reload")
        self.before = self.env.snell_snapshot()
        result = subprocess.run(["bash", str(SCRIPT), "--xray-uninstall-check"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("联动", result.stderr)
        self.assertEqual(systemctl("is-active", "xray.service"), "active")
        self.assert_snell()

    def test_stop_hook_is_not_executed(self):
        marker = Path("/root/xray-stop-hook-must-not-run")
        if marker.exists():
            marker.unlink()
        write("/etc/systemd/system/xray.service.d/test.conf", "[Service]\nExecStop=/usr/bin/touch /root/xray-stop-hook-must-not-run\n")
        systemctl("daemon-reload")
        result = subprocess.run(["bash", str(SCRIPT), "--xray-uninstall-check"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(systemctl("is-active", "xray.service"), "active")
        self.assert_snell()


if __name__ == "__main__":
    unittest.main()
