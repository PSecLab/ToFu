import unittest
from src.sanitizers.introspection import check_file_access, FileAccessTracer
from src.runners.python_runner import PythonRunner
from src.runners.base import RunnerResult

class TestIntrospectionSanitizers(unittest.TestCase):
    def test_check_file_access_restricted(self):
        accessed = ["/tmp/safe.txt", "/etc/passwd"]
        triggered, msg = check_file_access(accessed)
        self.assertTrue(triggered)
        self.assertIn("/etc/passwd", msg)

    def test_check_file_access_safe(self):
        accessed = ["/tmp/safe.txt", "/var/log/app.log"]
        triggered, msg = check_file_access(accessed)
        self.assertFalse(triggered)

    def test_file_access_tracer(self):
        tracer = FileAccessTracer()
        with tracer:
            try:
                open("/etc/passwd", "r")
            except Exception:
                pass
        self.assertIn("/etc/passwd", tracer.accessed_files)

if __name__ == "__main__":
    unittest.main()
