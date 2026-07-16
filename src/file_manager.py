import os
import tempfile
import logging

logger = logging.getLogger(__name__)

class FuzzFileManager:
    def __init__(self, file_backed_params: dict, seed_dir: str = None):
        self.file_backed_params = file_backed_params
        if seed_dir is None:
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
                
                scheme = config.get("scheme", "") or ""
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

    def _create_temp_file_for_bytes(self, val_bytes: bytes, config: dict) -> str:
        """Writes bytes buffer to a temporary file matching configured suffix extension."""
        suffix_config = config.get("extension", "") or config.get("extensions", "")
        if isinstance(suffix_config, list) and suffix_config:
            if len(val_bytes) > 0:
                ext_idx = val_bytes[0] % len(suffix_config)
                suffix_val = suffix_config[ext_idx]
                val_bytes = val_bytes[1:]
            else:
                suffix_val = suffix_config[0]
        else:
            suffix_val = suffix_config

        tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix_val)
        tf.write(val_bytes)
        tf.close()
        return tf.name

    def clean_temp_files(self, paths: list[str]) -> None:
        """Helper to remove temporary files."""
        for path in paths:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
