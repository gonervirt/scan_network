import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scanner


class AddressScopeTests(unittest.TestCase):
    def test_rejects_public_addresses_and_networks(self):
        with self.assertRaises(scanner.ScopeError):
            scanner.parse_addresses(["8.8.8.8/32"], None, [], 10)
        with self.assertRaises(scanner.ScopeError):
            scanner.parse_addresses([], None, [], 10)

    def test_rejects_cidr_before_expansion_when_limit_is_exceeded(self):
        with self.assertRaisesRegex(scanner.ScopeError, "exceeds"):
            scanner.parse_addresses(["10.0.0.0/8"], None, [], 10)

    def test_applies_address_and_network_exclusions(self):
        hosts = scanner.parse_addresses(["192.168.20.0/29"], None, ["192.168.20.2", "192.168.20.4/31"], 10)
        self.assertEqual(hosts, ["192.168.20.1", "192.168.20.3", "192.168.20.6"])

    def test_ip_file_is_validated_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ip_file = Path(temp_dir) / "hosts.txt"
            ip_file.write_text("10.1.0.1\n10.1.0.2\n", encoding="utf-8")
            self.assertEqual(scanner.parse_addresses([], str(ip_file), [], 2), ["10.1.0.1", "10.1.0.2"])
            with self.assertRaisesRegex(scanner.ScopeError, "exceeds"):
                scanner.parse_addresses([], str(ip_file), [], 1)


class OutputTests(unittest.TestCase):
    def test_ip_directory_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.assertEqual(scanner.safe_ip_dir(root, "192.168.1.4"), root / "4_192.168.1.4")

    def test_scan_writes_one_csv_row_per_ip_port_without_network(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "results.csv"

            def open_check(ip, port, timeout, limiter):
                return port == 80

            def detail(ip, port, work_dir, timeout, limiter):
                return {"ip": ip, "port": str(port), "status": "open", "service": "http"}

            with patch("scanner.port_is_open", side_effect=open_check), patch("scanner.probe_port", side_effect=detail):
                scanner.scan(["192.168.1.10"], (22, 80), output, root / "intermediate", 2, 10, 1)

            with output.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([(row["ip"], row["port"], row["status"]) for row in rows], [
                ("192.168.1.10", "80", "open"),
            ])

            with patch("scanner.port_is_open", side_effect=AssertionError("completed scan should not repeat")):
                scanner.scan(["192.168.1.10"], (22, 80), output, root / "intermediate", 2, 10, 1)

            with output.open(newline="", encoding="utf-8") as stream:
                resumed_rows = list(csv.DictReader(stream))
            self.assertEqual(len(resumed_rows), 1)

    def test_legacy_state_does_not_hide_results_when_csv_has_only_header(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "results.csv"
            work_dir = root / "intermediate"
            work_dir.mkdir()
            output.write_text(",".join(scanner.CSV_FIELDS) + "\n", encoding="utf-8")
            (work_dir / "scan_state.json").write_text(
                json.dumps({"completed": [["192.168.1.10", "80"]]}),
                encoding="utf-8",
            )

            with patch("scanner.port_is_open", return_value=True), patch(
                "scanner.probe_port",
                return_value={"ip": "192.168.1.10", "port": "80", "status": "open", "service": "http"},
            ):
                scanner.scan(["192.168.1.10"], (80,), output, work_dir, 1, 10, 1)

            with output.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "open")

    def test_save_completed_retries_temporary_permission_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "scan_state.json"
            replace = scanner.os.replace
            attempts = 0

            def replace_after_lock(source, destination):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise PermissionError("file is temporarily locked")
                replace(source, destination)

            with patch("scanner.os.replace", side_effect=replace_after_lock), patch("scanner.time.sleep"):
                scanner._save_completed(state_path, {("192.168.1.10", "22")})

            self.assertEqual(attempts, 2)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8")),
                {"closed": [["192.168.1.10", "22"]]},
            )
            self.assertEqual(list(Path(temp_dir).iterdir()), [state_path])

    def test_save_completed_cleans_temporary_file_after_replace_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "scan_state.json"
            state_path.write_text('{"closed":[]}', encoding="utf-8")

            with patch("scanner.os.replace", side_effect=PermissionError("file is locked")), patch("scanner.time.sleep"):
                with self.assertRaises(PermissionError):
                    scanner._save_completed(state_path, {("192.168.1.10", "22")})

            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), {"closed": []})
            self.assertEqual(list(Path(temp_dir).iterdir()), [state_path])


if __name__ == "__main__":
    unittest.main()