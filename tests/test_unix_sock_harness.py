import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
import os

from harnesses.unix_sock_fuzzer import run_harness, VALID_OBSERVABLES


class TestUnixSockHarness(unittest.TestCase):
    def test_dgram_socket_binding_and_cleanup(self):
        with TemporaryDirectory() as td:
            os.environ["DREAM_WORKSPACE"] = td
            params = {
                "sock_type": "dgram",
                "use_abstract": False,
                "pass_descriptor": False,
                "socket_name": "test_dgram.sock",
                "payload_len": 32,
            }
            res = run_harness(params)
            self.assertEqual(res["exit_code"], 0)
            self.assertTrue(res["probes"]["socket_bound"])
            self.assertFalse(res["probes"]["abstract_leaked"])

    def test_scm_rights_descriptor_passing(self):
        with TemporaryDirectory() as td:
            os.environ["DREAM_WORKSPACE"] = td
            params = {
                "sock_type": "stream",
                "use_abstract": False,
                "pass_descriptor": True,
                "socket_name": "test_scm.sock",
                "payload_len": 16,
            }
            res = run_harness(params)
            self.assertEqual(res["exit_code"], 0)
            self.assertTrue(res["probes"]["socket_bound"])

    def test_abstract_namespace_flag(self):
        params = {
            "sock_type": "dgram",
            "use_abstract": True,
            "pass_descriptor": False,
            "socket_name": "dream_abstract_probe_1",
            "payload_len": 16,
        }
        res = run_harness(params)
        self.assertEqual(res["exit_code"], 0)
        if res["probes"]["socket_bound"]:
            self.assertTrue(res["probes"]["abstract_leaked"])


if __name__ == "__main__":
    unittest.main()
