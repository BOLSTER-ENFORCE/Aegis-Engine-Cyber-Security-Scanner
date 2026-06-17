import json
from unittest.mock import MagicMock, patch

from django.test import TestCase

from myapp.scanner_backend import (
    get_extended_hardware_specs,
    get_external_ip,
    get_uptime,
    is_admin,
    profile_system_details,
    run_powershell_cmd,
)


# ------------------------------------------------------------------
# is_admin
# ------------------------------------------------------------------
class IsAdminTests(TestCase):
    def test_returns_false_on_linux(self):
        self.assertFalse(is_admin())


# ------------------------------------------------------------------
# get_uptime
# ------------------------------------------------------------------
class GetUptimeTests(TestCase):
    def test_returns_string(self):
        result = get_uptime()
        self.assertIsInstance(result, str)

    def test_contains_minute_marker(self):
        result = get_uptime()
        self.assertRegex(result, r"\d+m")

    @patch("myapp.scanner_backend.psutil.boot_time", side_effect=Exception("fail"))
    def test_exception_returns_unknown(self, _mock):
        self.assertEqual(get_uptime(), "Unknown")


# ------------------------------------------------------------------
# get_external_ip
# ------------------------------------------------------------------
class GetExternalIpTests(TestCase):
    @patch("urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"ip": "1.2.3.4"}).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        self.assertEqual(get_external_ip(), "1.2.3.4")

    @patch("urllib.request.urlopen", side_effect=Exception("network error"))
    def test_failure(self, _mock):
        result = get_external_ip()
        self.assertIn("Offline", result)


# ------------------------------------------------------------------
# profile_system_details
# ------------------------------------------------------------------
class ProfileSystemDetailsTests(TestCase):
    def test_returns_dict(self):
        result = profile_system_details()
        self.assertIsInstance(result, dict)

    def test_has_hostname(self):
        result = profile_system_details()
        self.assertIn("hostname", result)
        self.assertIsInstance(result["hostname"], str)

    def test_has_cpu_fields(self):
        result = profile_system_details()
        self.assertIn("cpu_physical_cores", result)
        self.assertIn("cpu_logical_cores", result)

    def test_has_ram(self):
        result = profile_system_details()
        self.assertIn("ram_total_gb", result)
        self.assertGreater(result["ram_total_gb"], 0)

    def test_has_disks_list(self):
        result = profile_system_details()
        self.assertIsInstance(result["disks"], list)

    def test_has_network_adapters(self):
        result = profile_system_details()
        self.assertIsInstance(result["network_adapters"], list)


# ------------------------------------------------------------------
# run_powershell_cmd (not on Windows, should return "")
# ------------------------------------------------------------------
class RunPowershellCmdTests(TestCase):
    def test_returns_empty_on_linux(self):
        result = run_powershell_cmd("Get-Process")
        self.assertEqual(result, "")


# ------------------------------------------------------------------
# get_extended_hardware_specs
# ------------------------------------------------------------------
class GetExtendedHardwareSpecsTests(TestCase):
    def test_returns_dict(self):
        result = get_extended_hardware_specs()
        self.assertIsInstance(result, dict)

    def test_has_swap_memory(self):
        result = get_extended_hardware_specs()
        self.assertIn("swap_memory", result)

    def test_has_net_io(self):
        result = get_extended_hardware_specs()
        self.assertIn("net_io", result)

    def test_has_disk_io(self):
        result = get_extended_hardware_specs()
        self.assertIn("disk_io", result)

    def test_has_cpu_freq(self):
        result = get_extended_hardware_specs()
        self.assertIn("cpu_freq", result)
