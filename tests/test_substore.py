"""Sub-Store regression checks; real Compose validation, no container mutations.

Run: python3 -m unittest discover -s tests -v
Requires Docker Compose v2 (the daemon does not need to be running).
"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = (Path(__file__).resolve().parents[1] / "net-tcp-tune.sh").read_text()


def function(name):
    return re.search(r"^" + name + r"\(\) \{\n.*?^\}", SCRIPT, re.M | re.S)[0]


HELPERS = SCRIPT[SCRIPT.index("substore_compose() {"):SCRIPT.index("# 检查端口是否被占用", SCRIPT.index("substore_compose() {"))]


class SubStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / "store-1.yaml"
        self.calls = self.root / "calls"
        self.tunnels = self.root / "tunnels"
        self.tunnels.mkdir()
        self.write_config()

    def write_config(self, cors=None):
        self.config.write_text("""services:
  sub-store-1:
    image: xream/sub-store:http-meta
    container_name: sub-store-1
    network_mode: host
    environment:
      SUB_STORE_BACKEND_API_HOST: 127.0.0.1
      SUB_STORE_BACKEND_API_PORT: 3001
      SUB_STORE_BACKEND_MERGE: true
      SUB_STORE_FRONTEND_BACKEND_PATH: /test-prefix
      HOST: 127.0.0.1
""" + (f"      SUB_STORE_CORS_ALLOWED_ORIGINS: {json.dumps(cors)}\n" if cors is not None else "") + """    volumes:
      - /tmp/substore-regression-data:/opt/app/data
""")

    def run_bash(self, code, stdin="", extra=""):
        # Only config operations reach Docker. Anything that could mutate is intercepted.
        harness = HELPERS + """
substore_compose() {
    case " $* " in
        *' config '*) command docker compose "$@" ;;
        *) printf '%s\\n' "$*" >> "$CALLS"; return "${MUTATION_RC:-0}" ;;
    esac
}
""" + extra + "\n" + code
        env = dict(os.environ, CONFIG=str(self.config), CF_CONFIGS_DIR=str(self.tunnels), CALLS=str(self.calls))
        return subprocess.run(["bash", "-c", harness], input=stdin, text=True, capture_output=True, env=env)

    def values(self):
        result = subprocess.check_output(["docker", "compose", "-f", str(self.config), "config", "--format", "json"])
        return json.loads(result)["services"]["sub-store-1"]

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_origin_validation(self):
        valid = ["https://sub.example.com", "http://127.0.0.1:3001", "http://[::1]:3001", "https://a.test,https://b.test"]
        invalid = ["", "*", "https://a.test/path", "https://a.test/", "https://u:p@a.test", "https://a.test:65536", "https://a.test:0", "https://a.test,", "https://a.test,,https://b.test", "https://a.test\nmalicious: value", "https://a.test?x=1"]
        for value in valid + invalid:
            with self.subTest(value=value):
                result = self.run_bash("validate_substore_origins " + shlex.quote(value))
                self.assertEqual(result.returncode == 0, value in valid, result.stderr)

    def test_missing_cors_migration_preserves_other_fields_and_backup(self):
        original = self.config.read_bytes()
        before = self.values()
        self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1 https://sub.example.com'))
        after = self.values()
        self.assertEqual(after["environment"].pop("SUB_STORE_CORS_ALLOWED_ORIGINS"), "https://sub.example.com")
        self.assertEqual(after, before)
        backups = list(self.root.glob("*.bak-cors.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1 https://sub.example.com'))
        self.assertEqual(len(list(self.root.glob("*.bak-cors.*"))), 1)

    def test_existing_allowlist_is_byte_preserved(self):
        for origin in ["https://custom.test,https://other.test", "*"]:
            self.write_config(origin)
            before = self.config.read_bytes()
            self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1'))
            self.assertEqual(self.config.read_bytes(), before)

    def test_tunnel_domain_appends_to_existing_allowlist(self):
        self.write_config("https://custom.test")
        self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1 https://new.test'))
        self.assertEqual(self.values()["environment"]["SUB_STORE_CORS_ALLOWED_ORIGINS"], "https://custom.test,https://new.test")

    def test_infer_domain_only_from_matching_instance_and_port(self):
        for filename in ["sub-store-1.yml", "sub-store-cf-tunnel-1.yaml"]:
            with self.subTest(filename=filename):
                self.write_config()
                for path in self.tunnels.iterdir():
                    path.unlink()
                (self.tunnels / filename).write_text("""ingress:
  - hostname: correct.test
    service: http://127.0.0.1:3001
  - hostname: unrelated.test
    service: http://127.0.0.1:9999
  - service: http_status:404
""")
                (self.tunnels / "sub-store-2.yml").write_text("  - hostname: wrong-instance.test\n    service: http://127.0.0.1:3001\n")
                self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1'))
                self.assertEqual(self.values()["environment"]["SUB_STORE_CORS_ALLOWED_ORIGINS"], "https://correct.test")

    def test_empty_setting_and_manual_migration(self):
        self.write_config("")
        self.assert_ok(self.run_bash('substore_ensure_cors "$CONFIG" 1', stdin="https://manual.test\n"))
        self.assertEqual(self.values()["environment"]["SUB_STORE_CORS_ALLOWED_ORIGINS"], "https://manual.test")

    def test_cancel_or_eof_does_not_touch_config(self):
        before = self.config.read_bytes()
        for stdin in ["", "\n"]:
            self.assertNotEqual(self.run_bash('substore_ensure_cors "$CONFIG" 1', stdin=stdin).returncode, 0)
            self.assertEqual(self.config.read_bytes(), before)

    def test_failed_validation_preserves_original(self):
        before = self.config.read_bytes()
        result = self.run_bash('substore_ensure_cors "$CONFIG" 1 https://sub.test', extra='substore_compose() { [[ "$*" != *--quiet* ]] && command docker compose "$@"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), before)

    def test_pull_failure_never_stops_or_recreates_container(self):
        self.write_config("https://sub.test")
        result = self.run_bash('MUTATION_RC=1; substore_update_one "$CONFIG" 1')
        self.assertNotEqual(result.returncode, 0)
        calls = self.calls.read_text()
        self.assertIn("pull sub-store-1", calls)
        self.assertNotIn(" down", calls)
        self.assertNotIn(" up", calls)
        self.assertNotIn("更新完成", result.stdout)

    def test_update_success_checks_origin_and_uses_no_down(self):
        self.write_config("https://sub.test,https://other.test")
        result = self.run_bash('substore_update_one "$CONFIG" 1', extra='curl() { printf "%s\\n" "$*" >> "$CALLS"; echo \'{"status":"success"}\'; }')
        self.assert_ok(result)
        calls = self.calls.read_text()
        self.assertIn("up -d --no-deps sub-store-1", calls)
        self.assertNotIn(" down", calls)
        self.assertIn("Origin: https://sub.test", calls)
        self.assertIn("Origin: https://other.test", calls)
        self.assertIn("http://127.0.0.1:3001/test-prefix/api/utils/env", calls)

    def test_403_prevents_false_success(self):
        self.write_config("https://sub.test")
        result = self.run_bash('substore_update_one "$CONFIG" 1', extra='curl() { return 22; }; sleep() { :; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("更新完成", result.stdout)

    def test_all_instances_reports_partial_failure(self):
        extra = function("update_substore_instance") + """
clear() { :; }
break_end() { :; }
get_substore_instances() { echo 'store-1 store-2'; }
docker() { echo sub-store-1; }
substore_update_one() { [[ "$2" = 1 ]]; }
"""
        result = self.run_bash("update_substore_instance", stdin="3\ny\n", extra=extra)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1 个实例未完成", result.stdout)
        self.assertNotIn("所有实例更新完成", result.stdout)

    def test_install_wizard_writes_cors_and_checks_origin(self):
        # Redirect the wizard's filesystem paths; neither Docker nor CF mutates.
        extra = "\n".join(function(name) for name in ["validate_substore_port", "validate_substore_path", "install_substore_instance"])
        extra = extra.replace("/root/sub-store-configs", str(self.root)).replace("/root/sub-store-cf-tunnel-", str(self.root / "cf-"))
        extra += """
clear() { :; }
break_end() { :; }
check_substore_docker() { return 0; }
get_substore_instances() { :; }
check_substore_instance_exists() { return 1; }
check_substore_port() { return 0; }
generate_substore_random_path() { echo random-test; }
curl() { printf '%s\\n' "$*" >> "$CALLS"; echo '{"status":"success"}'; }
"""
        stdin = f"1\n3001\ntest-prefix\n{self.root / 'data'}\nhttps://install.test\ny\n2\n"
        self.assert_ok(self.run_bash("install_substore_instance", stdin=stdin, extra=extra))
        self.assertEqual(self.values()["environment"]["SUB_STORE_CORS_ALLOWED_ORIGINS"], "https://install.test")
        self.assertIn("Origin: https://install.test", self.calls.read_text())

    def test_tunnel_wizard_adds_domain_before_creating_tunnel(self):
        self.write_config("https://sub-store.vercel.app")
        extra = function("cf_tunnel_deploy_for_substore").replace("/root/sub-store-configs", str(self.root))
        extra += """
clear() { :; }
cf_helper_install_binary() { return 0; }
cf_helper_ensure_auth() { return 0; }
curl() { printf '%s\\n' "$*" >> "$CALLS"; echo '{"status":"success"}'; }
# Stop before any external tunnel operations; assert that CORS setup already happened.
cf_helper_create_tunnel() { echo create-tunnel >> "$CALLS"; return 1; }
"""
        result = self.run_bash("cf_tunnel_deploy_for_substore 1 3001 test-prefix", stdin="sub.example.com\ny\n", extra=extra)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.values()["environment"]["SUB_STORE_CORS_ALLOWED_ORIGINS"], "https://sub-store.vercel.app,https://sub.example.com")
        calls = self.calls.read_text()
        self.assertLess(calls.index("Origin: https://sub.example.com"), calls.index("create-tunnel"))

    def test_nonstandard_layout_fails_without_rewriting(self):
        self.config.write_text(self.config.read_text().replace("    environment:\n", "    environment: # user layout\n"))
        before = self.config.read_bytes()
        result = self.run_bash('substore_ensure_cors "$CONFIG" 1 https://sub.test')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
