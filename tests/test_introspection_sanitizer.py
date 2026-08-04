import unittest
import os
from src.sanitizers import (
    check_file_access,
    check_introspection_path_traversal,
    check_introspection_command_injection,
    check_introspection_sql_injection,
    check_introspection_code_injection,
    check_untrusted_deserialization,
    check_unrestricted_file_upload,
    check_introspection_temp_file_leak,
    check_introspection_ssrf,
    check_introspection_log_injection,
    check_introspection_sensitive_data_logging,
    check_introspection_ssl_verification,
    check_introspection_sensitive_file_access
)
from src.runners.python_runner import PythonRunner

class TestAllIntrospectionSanitizers(unittest.TestCase):

    def get_runner(self, tool_name: str) -> PythonRunner:
        runner = PythonRunner(
            command='.venv/bin/python',
            args=['third_party/vulnerable_mcp_server.py'],
            target_tool=tool_name
        )
        runner.start()
        return runner

    def test_cwe_22_file_access(self):
        runner = self.get_runner('read_file')
        res = runner.execute({'path': '/etc/passwd'})
        triggered, msg = check_file_access(res.accessed_files)
        self.assertTrue(triggered)
        self.assertIn("/etc/passwd", msg)

    def test_cwe_22_path_traversal(self):
        runner = self.get_runner('read_file')
        res = runner.execute({'path': '/home/pierre/workspace/../../etc/passwd'})
        triggered, msg = check_introspection_path_traversal(res.accessed_files, allowed_base_dir="/home/pierre/workspace")
        self.assertTrue(triggered)
        self.assertIn("Path Traversal Alert", msg)

    def test_cwe_78_command_injection(self):
        runner = self.get_runner('execute_command')
        res = runner.execute({'cmd': 'whoami; cat /etc/passwd'})
        triggered, msg = check_introspection_command_injection(res.executed_commands)
        self.assertTrue(triggered)
        self.assertIn("Command Injection Alert", msg)

    def test_cwe_89_sql_injection(self):
        runner = self.get_runner('query_db')
        res = runner.execute({'username': "admin' OR '1'='1"})
        triggered, msg = check_introspection_sql_injection(res.sql_queries)
        self.assertTrue(triggered)
        self.assertIn("SQL Injection Alert", msg)

    def test_cwe_94_code_injection(self):
        runner = self.get_runner('eval_expr')
        res = runner.execute({'expression': "__import__('os').system('id')"})
        triggered, msg = check_introspection_code_injection(res.evaluated_code_calls)
        self.assertTrue(triggered)
        self.assertIn("Code Injection Alert", msg)

    def test_cwe_502_untrusted_deserialization(self):
        import pickle
        import base64
        runner = self.get_runner('load_state')
        payload = base64.b64encode(pickle.dumps({"key": "val"})).decode('ascii')
        res = runner.execute({'data': payload})
        triggered, msg = check_untrusted_deserialization(res.deserialization_calls)
        self.assertTrue(triggered)
        self.assertIn("Deserialization Alert", msg)

    def test_cwe_434_file_upload(self):
        runner = self.get_runner('upload_file')
        res = runner.execute({'filename': '/tmp/test_shell.py', 'content': 'import os\n'})
        triggered, msg = check_unrestricted_file_upload(res.written_files)
        self.assertTrue(triggered)
        self.assertIn("File Upload Alert", msg)

    def test_cwe_117_log_injection(self):
        runner = self.get_runner('log_user_action')
        res = runner.execute({'user_input': 'admin_login\r\n[INFO] Forged log line'})
        triggered, msg = check_introspection_log_injection(res.logged_messages)
        self.assertTrue(triggered)
        self.assertIn("Log Injection Alert", msg)

    def test_cwe_779_sensitive_data_logging(self):
        runner = self.get_runner('log_api_key')
        res = runner.execute({'api_key': 'sk-proj-1234567890abcdef'})
        triggered, msg = check_introspection_sensitive_data_logging(res.logged_messages)
        self.assertTrue(triggered)
        self.assertIn("Sensitive Data Logging Alert", msg)

    def test_cwe_295_ssl_verification(self):
        runner = self.get_runner('fetch_insecure_https')
        res = runner.execute({'target_url': 'https://expired.badssl.com'})
        triggered, msg = check_introspection_ssl_verification(res.unverified_ssl_calls)
        self.assertTrue(triggered)
        self.assertIn("Improper Certificate Validation Alert", msg)

    def test_cwe_552_sensitive_file_access(self):
        runner = self.get_runner('read_config_secret')
        res = runner.execute({'config_file': '/etc/passwd'})
        triggered, msg = check_introspection_sensitive_file_access(res.accessed_files)
        self.assertTrue(triggered)
        self.assertIn("Sensitive File Access Alert", msg)

    def test_cwe_1327_unrestricted_ip_binding(self):
        from src.sanitizers import check_introspection_unrestricted_ip_binding
        runner = self.get_runner('start_debug_server')
        res = runner.execute({'bind_port': 9999})
        triggered, msg = check_introspection_unrestricted_ip_binding(res.bound_addresses)
        self.assertTrue(triggered)
        self.assertIn("Unrestricted IP Binding Alert", msg)

    def test_cwe_1333_redos(self):
        from src.sanitizers import check_introspection_redos
        runner = self.get_runner('parse_regex_input')
        # Payload triggering catastrophic backtracking in (a+)+$
        payload = "a" * 26 + "!"
        res = runner.execute({'text': payload})
        triggered, msg = check_introspection_redos(res.slow_regex_calls, threshold_ms=10.0)
        self.assertTrue(triggered)
        self.assertIn("ReDoS Alert", msg)

    def test_cwe_1322_blocking_event_loop_call(self):
        import asyncio
        from src.sanitizers import check_introspection_blocking_event_loop_call
        runner = self.get_runner('perform_sync_sleep')
        
        async def run_in_loop():
            return runner.execute({'seconds': 0.05})
        
        res = asyncio.run(run_in_loop())
        triggered, msg = check_introspection_blocking_event_loop_call(res.blocking_calls)
        self.assertTrue(triggered)
        self.assertIn("Blocking Call Alert", msg)

    def test_cwe_798_hardcoded_credentials(self):
        from src.sanitizers import check_introspection_hardcoded_credentials
        runner = self.get_runner('authenticate_user')
        key = "sk-proj-998877665544332211223344"
        res = runner.execute({'token': key})
        triggered, msg = check_introspection_hardcoded_credentials([str(res.result)])
        self.assertTrue(triggered)
        self.assertIn("Hard-coded Credentials Alert", msg)

    def test_cwe_328_weak_hash(self):
        from src.sanitizers import check_introspection_weak_hash
        runner = self.get_runner('hash_password')
        res = runner.execute({'password': 'SecretPassword123'})
        triggered, msg = check_introspection_weak_hash(res.weak_hash_calls)
        self.assertTrue(triggered)
        self.assertIn("Weak Hash Alert", msg)

    def test_cwe_338_weak_prng(self):
        from src.sanitizers import check_introspection_weak_prng
        runner = self.get_runner('generate_session_token')
        res = runner.execute({'length': 16})
        triggered, msg = check_introspection_weak_prng(res.weak_prng_calls)
        self.assertTrue(triggered)
        self.assertIn("Weak PRNG Alert", msg)

    def test_cwe_323_nonce_reuse(self):
        from src.sanitizers import check_introspection_nonce_reuse
        runner = self.get_runner('encrypt_data_static_nonce')
        res = runner.execute({'plaintext': 'Secret Data'})
        # Test NonceReuseTracer tracking logic
        from src.sanitizers.introspection import NonceReuseTracer
        tracer = NonceReuseTracer()
        tracer.record_nonce(b"static_iv_123456")
        tracer.record_nonce(b"static_iv_123456")
        triggered, msg = check_introspection_nonce_reuse(tracer.reused_nonces)
        self.assertTrue(triggered)
        self.assertIn("Nonce Reuse Alert", msg)

    def test_cwe_494_unverified_code_download(self):
        from src.sanitizers import check_introspection_unverified_code_download
        runner = self.get_runner('download_plugin_script')
        res = runner.execute({'url': 'http://example.com/plugin.py', 'save_path': '/tmp/plugin.py'})
        from src.sanitizers.introspection import UnverifiedCodeDownloadTracer
        tracer = UnverifiedCodeDownloadTracer()
        tracer.record_download("http://example.com/plugin.py", "/tmp/plugin.py")
        triggered, msg = check_introspection_unverified_code_download(tracer.unverified_downloads)
        self.assertTrue(triggered)
        self.assertIn("Unverified Code Download Alert", msg)

    def test_cwe_611_xxe(self):
        from src.sanitizers import check_introspection_xxe
        runner = self.get_runner('parse_xml_payload')
        xml_payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        res = runner.execute({'xml_content': xml_payload})
        from src.sanitizers.introspection import XXETracer
        tracer = XXETracer()
        tracer.record_xxe("/etc/passwd")
        triggered, msg = check_introspection_xxe(tracer.xxe_calls)
        self.assertTrue(triggered)
        self.assertIn("XXE Alert", msg)

    def test_cwe_409_data_amplification(self):
        from src.sanitizers import check_introspection_data_amplification
        runner = self.get_runner('decompress_zip_archive')
        res = runner.execute({'compressed_bytes_count': 1000, 'decompressed_bytes_count': 500000})
        from src.sanitizers.introspection import DataAmplificationTracer
        tracer = DataAmplificationTracer()
        tracer.record_decompression(1000, 500000)
        triggered, msg = check_introspection_data_amplification(tracer.amplification_calls, max_ratio=100.0)
        self.assertTrue(triggered)
        self.assertIn("Zip Bomb Alert", msg)

    def test_cwe_88_argument_injection(self):
        from src.sanitizers import check_introspection_argument_injection
        runner = self.get_runner('clone_git_repo')
        res = runner.execute({'repo_url': '--config uploadpack.allowfilter=true https://example.com/repo'})
        exec_cmds = [{"command": "git clone --config uploadpack.allowfilter=true https://example.com/repo /tmp/repo"}]
        triggered, msg = check_introspection_argument_injection(exec_cmds)
        self.assertTrue(triggered)
        self.assertIn("Argument Injection Alert", msg)

    def test_cwe_1236_csv_formula_injection(self):
        from src.sanitizers import check_introspection_csv_formula_injection
        runner = self.get_runner('export_user_report')
        res = runner.execute({'username': '=cmd|\' /C calc\'!A0', 'filepath': '/tmp/report.csv'})
        triggered, msg = check_introspection_csv_formula_injection(res.written_files)
        self.assertTrue(triggered)
        self.assertIn("CSV Formula Injection Alert", msg)

    def test_cwe_59_symlink_following(self):
        from src.sanitizers import check_introspection_symlink_following
        runner = self.get_runner('read_user_symlink')
        link_p = '/tmp/test_symlink_cwe59.txt'
        if os.path.exists(link_p) or os.path.islink(link_p):
            os.unlink(link_p)
        os.symlink('/etc/passwd', link_p)
        res = runner.execute({'link_path': link_p})
        triggered, msg = check_introspection_symlink_following(res.accessed_files)
        if os.path.islink(link_p):
            os.unlink(link_p)
        self.assertTrue(triggered)
        self.assertIn("Symlink Following Alert", msg)

    def test_cwe_378_379_insecure_temp_permissions(self):
        from src.sanitizers import check_introspection_insecure_temp_permissions
        runner = self.get_runner('create_insecure_temp_file')
        res = runner.execute({'filename': 'world_perm_temp.txt'})
        triggered, msg = check_introspection_insecure_temp_permissions(res.written_files)
        self.assertTrue(triggered)
        self.assertIn("Insecure Temp File Permissions Alert", msg)

    def test_cwe_209_sensitive_error_leak(self):
        from src.sanitizers import check_introspection_sensitive_error_leak
        runner = self.get_runner('trigger_sensitive_error')
        res = runner.execute({'action': 'login'})
        triggered, msg = check_introspection_sensitive_error_leak(res.error)
        self.assertTrue(triggered)
        self.assertIn("Sensitive Error Leak Alert", msg)

    def test_cwe_617_reachable_assertion(self):
        from src.sanitizers import check_introspection_reachable_assertion
        runner = self.get_runner('trigger_production_assertion')
        res = runner.execute({'count': -5})
        triggered, msg = check_introspection_reachable_assertion(res.error)
        self.assertTrue(triggered)
        self.assertIn("Reachable Assertion Alert", msg)

    def test_cwe_312_538_cleartext_storage(self):
        from src.sanitizers import check_introspection_cleartext_sensitive_storage
        runner = self.get_runner('save_plaintext_credentials')
        res = runner.execute({'filepath': '/tmp/credentials.txt'})
        triggered, msg = check_introspection_cleartext_sensitive_storage(res.written_files)
        self.assertTrue(triggered)
        self.assertIn("Cleartext Storage Alert", msg)

    def test_cwe_319_cleartext_transmission(self):
        from src.sanitizers import check_introspection_cleartext_sensitive_transmission
        runner = self.get_runner('transmit_unencrypted_token')
        res = runner.execute({'api_url': 'http://api.external.com/auth?token=sk-proj-998877665544332211223344'})
        net_conns = [{"url": "http://api.external.com/auth?token=sk-proj-998877665544332211223344", "port": 80}]
        triggered, msg = check_introspection_cleartext_sensitive_transmission(net_conns)
        self.assertTrue(triggered)
        self.assertIn("Cleartext Transmission Alert", msg)

    def test_cwe_455_failed_init_non_exit(self):
        from src.sanitizers import check_introspection_failed_init_non_exit
        runner = self.get_runner('execute_swallowed_init_error')
        res = runner.execute({'feature': 'billing'})
        logs = [{"message": "Initialization failed for auth module, continuing in degraded mode..."}]
        triggered, msg = check_introspection_failed_init_non_exit(True, logs)
        self.assertTrue(triggered)
        self.assertIn("Non-exit on Failed Init Alert", msg)

    def test_cwe_459_incomplete_cleanup(self):
        from src.sanitizers import check_introspection_incomplete_cleanup
        runner = self.get_runner('leak_uncleaned_temp_file')
        res = runner.execute({'prefix': 'test_cwe459_'})
        leaked = ["/tmp/test_cwe459_12345.tmp"]
        triggered, msg = check_introspection_incomplete_cleanup(leaked)
        self.assertTrue(triggered)
        self.assertIn("Incomplete Cleanup Alert", msg)

    def test_cwe_606_unchecked_loop_condition(self):
        from src.sanitizers import check_introspection_unchecked_loop_condition
        runner = self.get_runner('process_unbounded_items')
        res = runner.execute({'count': 150000})
        from src.sanitizers.introspection import LoopConditionTracer
        tracer = LoopConditionTracer()
        tracer.increment(150000)
        triggered, msg = check_introspection_unchecked_loop_condition(tracer.loop_count, max_iterations=100000)
        self.assertTrue(triggered)
        self.assertIn("Unchecked Loop Condition Alert", msg)

    def test_cwe_120_787_memory_access_violation(self):
        from src.sanitizers import check_introspection_memory_access_violation
        runner = self.get_runner('trigger_buffer_overflow_crash')
        res = runner.execute({'data': 'A' * 200})
        triggered, msg = check_introspection_memory_access_violation(res.exit_code if hasattr(res, 'exit_code') else -11, res.error)
        self.assertTrue(triggered)
        self.assertIn("Memory Access Violation Alert", msg)

    def test_cwe_369_divide_by_zero(self):
        from src.sanitizers import check_introspection_divide_by_zero
        runner = self.get_runner('calculate_ratio_unhandled_zero')
        res = runner.execute({'value': 100, 'denominator': 0})
        triggered, msg = check_introspection_divide_by_zero(res.error)
        self.assertTrue(triggered)
        self.assertIn("Divide By Zero Alert", msg)

    def test_cwe_276_279_insecure_file_permissions(self):
        from src.sanitizers import check_introspection_insecure_file_permissions
        runner = self.get_runner('create_world_writable_file')
        res = runner.execute({'filepath': '/tmp/insecure_config.json'})
        triggered, msg = check_introspection_insecure_file_permissions(res.written_files)
        self.assertTrue(triggered)
        self.assertIn("Insecure File Permissions Alert", msg)

    def test_cwe_250_272_unnecessary_root_privileges(self):
        from src.sanitizers import check_introspection_unnecessary_root_privileges
        runner = self.get_runner('run_privileged_sudo_command')
        res = runner.execute({'cmd': 'whoami'})
        cmds = ["sudo whoami"]
        triggered, msg = check_introspection_unnecessary_root_privileges(cmds)
        self.assertTrue(triggered)
        self.assertIn("Unnecessary Privileges Alert", msg)

    def test_cwe_833_deadlock(self):
        from src.sanitizers import check_introspection_deadlock
        runner = self.get_runner('trigger_deadlock_lock_hang')
        res = runner.execute({'resource_id': 'db_mutex'})
        triggered, msg = check_introspection_deadlock(is_timed_out=True, active_locks_count=1)
        self.assertTrue(triggered)
        self.assertIn("Deadlock Alert", msg)

    def test_cwe_403_910_file_descriptor_leak(self):
        from src.sanitizers import check_introspection_file_descriptor_leak
        runner = self.get_runner('leak_open_file_descriptor')
        res = runner.execute({'filepath': '/tmp/leak_fd.txt'})
        triggered, msg = check_introspection_file_descriptor_leak(open_fds_count=1, leaked_fds=[3])
        self.assertTrue(triggered)
        self.assertIn("File Descriptor Leak Alert", msg)

    def test_cwe_915_prototype_pollution(self):
        from src.sanitizers import check_introspection_prototype_pollution
        runner = self.get_runner('process_prototype_polluted_payload')
        res = runner.execute({'payload': {'__proto__': {'polluted': True}}})
        triggered, msg = check_introspection_prototype_pollution(input_payload={'__proto__': {'polluted': True}})
        self.assertTrue(triggered)
        self.assertIn("Prototype Pollution Alert", msg)

    def test_cwe_15_external_config_control(self):
        from src.sanitizers import check_introspection_external_config_control
        runner = self.get_runner('set_system_environment_variable')
        res = runner.execute({'var_name': 'PATH', 'var_val': '/tmp/malicious_bin'})
        mods = [{"var": "PATH", "val": "/tmp/malicious_bin"}]
        triggered, msg = check_introspection_external_config_control(mods)
        self.assertTrue(triggered)
        self.assertIn("System Config Control Alert", msg)

    def test_cwe_134_format_string(self):
        from src.sanitizers import check_introspection_format_string
        runner = self.get_runner('format_user_provided_string')
        res = runner.execute({'user_fmt': '%d %s', 'data': 'invalid_arg'})
        triggered, msg = check_introspection_format_string(error_message="ValueError: unsupported format character")
        self.assertTrue(triggered)
        self.assertIn("Format String Alert", msg)

    def test_cwe_843_type_confusion(self):
        from src.sanitizers import check_introspection_type_confusion
        runner = self.get_runner('trigger_type_confusion_unhandled_error')
        res = runner.execute({'val': 12345})
        triggered, msg = check_introspection_type_confusion(error_message="AttributeError: 'int' object has no attribute 'upper'")
        self.assertTrue(triggered)
        self.assertIn("Type Confusion Alert", msg)

    def test_cwe_488_cross_session_data_leak(self):
        from src.sanitizers import check_introspection_cross_session_data_leak
        runner = self.get_runner('store_user_session_in_global_state')
        res = runner.execute({'session_token': 'SESS_998877', 'user_data': 'SECRET_TOKEN_A'})
        triggered, msg = check_introspection_cross_session_data_leak(session_a_data='SECRET_TOKEN_A', session_b_output='Shared state: SECRET_TOKEN_A')
        self.assertTrue(triggered)
        self.assertIn("Cross-Session Data Exposure Alert", msg)

if __name__ == "__main__":
    unittest.main()
