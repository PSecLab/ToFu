import json
import inspect
import atheris

class FuzzInputParser:
    def __init__(self, schema: dict, file_backed_params: dict, current_runner):
        self.schema = schema
        self.file_backed_params = file_backed_params
        self.current_runner = current_runner

    def parse(self, data: bytes) -> tuple[dict, bool]:
        """Parses inputs using either JSON parsing or fallback generators."""
        properties = self.schema.get("properties", {})
        sig = self._get_runner_signature()

        # Try JSON first
        generated_arguments, parsed_successfully = self._try_parse_json(data, properties)

        # Fallback to FuzzedDataProvider if JSON failed
        if not parsed_successfully:
            generated_arguments = self._generate_fallback_inputs(data, properties, sig)

        # Decode base64 / string representation if JSON parsed successfully
        if parsed_successfully:
            generated_arguments = self._decode_bytes_arguments(generated_arguments, sig)

        return generated_arguments, parsed_successfully

    def _get_runner_signature(self):
        """Extracts the signature of the target function if available."""
        if hasattr(self.current_runner, "target_func") and self.current_runner.target_func:
            try:
                return inspect.signature(self.current_runner.target_func)
            except Exception:
                pass
        return None

    def _try_parse_json(self, data: bytes, properties: dict) -> tuple[dict, bool]:
        """Attempts to parse input data as JSON matching the schema properties."""
        generated_arguments = {}
        try:
            decoded_str = data.decode("utf-8", errors="ignore")
            parsed_json = json.loads(decoded_str)
            if isinstance(parsed_json, dict):
                for prop_name in properties:
                    if prop_name in parsed_json:
                        generated_arguments[prop_name] = parsed_json[prop_name]
                    else:
                        raise ValueError("Missing property")
                return generated_arguments, True
        except Exception:
            pass
        return {}, False

    def _generate_fallback_inputs(self, data: bytes, properties: dict, sig) -> dict:
        """Generates random mock inputs using FuzzedDataProvider."""
        fdp = atheris.FuzzedDataProvider(data)
        generated_arguments = {}
        for prop_name, prop_attrs in properties.items():
            is_bytes = self._is_bytes_parameter(prop_name, sig) or (prop_name in self.file_backed_params)

            if is_bytes:
                generated_arguments[prop_name] = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
            else:
                prop_type = prop_attrs.get("type")
                if prop_type == "string":
                    generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))
                elif prop_type == "integer":
                    generated_arguments[prop_name] = fdp.ConsumeInt(4)
                elif prop_type == "number":
                    generated_arguments[prop_name] = fdp.ConsumeFloat()
                elif prop_type == "boolean":
                    generated_arguments[prop_name] = fdp.ConsumeBool()
                else:
                    generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
        return generated_arguments

    def _is_bytes_parameter(self, prop_name: str, sig) -> bool:
        """Determines if a parameter expects raw bytes annotation."""
        if sig and prop_name in sig.parameters:
            param = sig.parameters[prop_name]
            return param.annotation in (bytes, "bytes") or "bytes" in str(param.annotation)
        return False

    def _decode_bytes_arguments(self, generated_arguments: dict, sig) -> dict:
        """Post-processes parsed JSON string/base64 arguments back into bytes where needed."""
        updated = generated_arguments.copy()
        for prop_name, val in list(updated.items()):
            is_bytes = self._is_bytes_parameter(prop_name, sig) or (prop_name in self.file_backed_params)
            
            if is_bytes and not isinstance(val, bytes):
                if isinstance(val, str):
                    import base64
                    try:
                        updated[prop_name] = base64.b64decode(val.encode("utf-8"))
                    except Exception:
                        updated[prop_name] = val.encode("utf-8", errors="ignore")
                else:
                    updated[prop_name] = str(val).encode("utf-8")
        return updated
