import os
import tempfile
import logging

logger = logging.getLogger(__name__)

class FuzzFileManager:
    def __init__(self, file_backed_params: dict, seed_dir: str = None):
        self.file_backed_params = file_backed_params
        if seed_dir is None:
            # Must agree with seed_generators.SEED_DIR, or a run writes a
            # predefined seed to one directory and resolves it from another.
            env_dir = os.environ.get("TOFU_SEED_DIR")
            if env_dir:
                self.seed_dir = env_dir
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                self.seed_dir = os.path.join(base_dir, "predefined_seeds")
        else:
            self.seed_dir = seed_dir

    def prepare_file_params(self, generated_arguments: dict) -> tuple[dict, list[str]]:
        """Handles creating temporary files for parameters that expect a file path/URI."""
        created_temp_files = []
        updated_args = generated_arguments.copy()
        
        for prop_name, config in self.file_backed_params.items():
            if prop_name in updated_args:
                val = updated_args[prop_name]
                is_predefined, seed_bytes = self._read_predefined_seed(val)
                
                val_bytes = seed_bytes if is_predefined else val
                if not isinstance(val_bytes, bytes):
                    if isinstance(val_bytes, str):
                        val_bytes = val_bytes.encode('utf-8', errors='ignore')
                    else:
                        val_bytes = str(val_bytes).encode('utf-8')
                
                temp_file = self._create_temp_file_for_bytes(val_bytes, config)
                created_temp_files.append(temp_file)
                
                scheme = config.get("scheme", "") if isinstance(config, dict) else ""
                updated_args[prop_name] = f"{scheme}{temp_file}"

        return updated_args, created_temp_files

    def _read_predefined_seed(self, val) -> tuple[bool, bytes]:
        """Resolves predefined seed value to actual bytes if matching format."""
        is_predefined = False
        filename = ""
        
        if isinstance(val, str) and val.startswith("predefined_seed:"):
            is_predefined = True
            filename = val.split(":", 1)[1]
        elif isinstance(val, bytes) and val.startswith(b"predefined_seed:"):
            is_predefined = True
            try:
                filename = val.decode('utf-8', errors='ignore').split(":", 1)[1]
            except Exception:
                is_predefined = False

        if is_predefined:
            seed_path = os.path.join(self.seed_dir, filename)
            if os.path.exists(seed_path):
                try:
                    with open(seed_path, "rb") as sf:
                        return True, sf.read()
                except Exception as e:
                    logger.error(f"Failed to read predefined seed {filename}: {e}")
            else:
                logger.error(f"Predefined seed {filename} not found at {seed_path}")
        return False, b""

    def _create_temp_file_for_bytes(self, val_bytes: bytes, config: any) -> str:
        """Writes bytes buffer to a temporary file matching configured suffix extension."""
        if isinstance(config, str):
            suffix_config = os.path.splitext(config)[1]
        elif isinstance(config, dict):
            suffix_config = config.get("extension", "") or config.get("extensions", "")
        else:
            suffix_config = ""
        if isinstance(suffix_config, list) and suffix_config:
            if len(val_bytes) > 0:
                ext_idx = val_bytes[0] % len(suffix_config)
                suffix_val = suffix_config[ext_idx]
                val_bytes = val_bytes[1:]
            else:
                suffix_val = suffix_config[0]
        else:
            suffix_val = suffix_config

        # Apply structure-aware mutations for JSON-based file types
        if suffix_val in (".json", ".heapsnapshot"):
            val_bytes = self._mutate_json_structurally(val_bytes, suffix_val)

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix_val)
        tf.write(val_bytes)
        tf.close()
        return tf.name

    def _mutate_json_structurally(self, val_bytes: bytes, extension: str) -> bytes:
        """Attempts to parse val_bytes as JSON. If it fails, falls back to a template seed
        and mutates its structure using val_bytes to ensure it remains a valid JSON document."""
        import json
        
        # 1. Try to load the incoming bytes as JSON first
        try:
            data = json.loads(val_bytes.decode('utf-8', errors='ignore'))
            if isinstance(data, (dict, list)):
                return json.dumps(data).encode('utf-8')
        except Exception:
            pass

        # 2. Fallback: Load a valid template seed
        seed_name = "sample.heapsnapshot" if extension == ".heapsnapshot" else "nested.json"
        seed_path = os.path.join(self.seed_dir, seed_name)
        
        if not os.path.exists(seed_path):
            data = {"snapshot": {"meta": {}, "node_count": 0}, "nodes": [], "edges": [], "strings": []}
        else:
            try:
                with open(seed_path, "r", encoding="utf-8") as sf:
                    data = json.load(sf)
            except Exception:
                data = {}

        # 3. Mutate the JSON structure using val_bytes as a source of mutation commands
        if not val_bytes:
            return json.dumps(data).encode('utf-8')

        byte_idx = 0
        def get_byte_val(default=0):
            nonlocal byte_idx
            if byte_idx < len(val_bytes):
                v = val_bytes[byte_idx]
                byte_idx += 1
                return v
            return default

        def mutate_value(val):
            b = get_byte_val()
            if b % 5 == 0:  # 20% chance to mutate value
                if isinstance(val, bool):
                    return not val
                elif isinstance(val, (int, float)):
                    # Mutate number to edge cases
                    cases = [0, -1, 999999, None, val * 2, val // 2 if val else 1]
                    return cases[get_byte_val() % len(cases)]
                elif isinstance(val, str):
                    str_cases = ["", "\0", "%s%d%x", "A" * 1000, "127.0.0.1", "../../etc/passwd"]
                    return str_cases[get_byte_val() % len(str_cases)]
            return val

        def walk_and_mutate(node):
            if isinstance(node, dict):
                for k in list(node.keys()):
                    b = get_byte_val()
                    if b % 20 == 0:
                        del node[k]
                    elif b % 20 == 1:
                        node[k + "_fuzzed"] = walk_and_mutate(node.pop(k))
                    else:
                        node[k] = walk_and_mutate(node[k])
            elif isinstance(node, list):
                b = get_byte_val()
                if b % 15 == 0 and len(node) > 0:
                    node[:] = node[:get_byte_val() % len(node)]
                elif b % 15 == 1 and len(node) > 0:
                    node.extend(node[:get_byte_val() % len(node)])
                
                for i in range(len(node)):
                    node[i] = walk_and_mutate(node[i])
            else:
                return mutate_value(node)
            return node

        try:
            walked_data = walk_and_mutate(data)
            serialized = json.dumps(walked_data, allow_nan=False)
            return serialized.encode('utf-8')
        except Exception:
            try:
                return json.dumps(data).encode('utf-8')
            except Exception:
                return b"{}"

    def clean_temp_files(self, paths: list[str]) -> None:
        """Helper to remove temporary files."""
        for path in paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
