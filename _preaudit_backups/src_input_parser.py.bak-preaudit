import json
import inspect
import atheris

class FuzzInputParser:
    def __init__(self, schema: dict, file_backed_params: dict, current_runner):
        self.schema = schema
        self.file_backed_params = file_backed_params
        self.current_runner = current_runner

    def parse(self, data: bytes) -> tuple[dict, bool]:
        """Parses inputs using schema-aware FuzzedDataProvider or JSON parsing."""
        properties = self.schema.get("properties", {})
        sig = self._get_runner_signature()

        # 1. Try schema-conforming structure generation with Atheris FuzzedDataProvider
        if properties:
            try:
                generated_arguments = self._generate_fallback_inputs(data, properties, sig)
                if generated_arguments:
                    return generated_arguments, True
            except Exception:
                pass

        # 2. Try raw JSON parsing fallback
        generated_arguments, parsed_successfully = self._try_parse_json(data, properties)

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
                # If properties schema is defined, extract matched properties or keep parsed_json
                if properties:
                    matched = 0
                    for prop_name in properties:
                        if prop_name in parsed_json:
                            generated_arguments[prop_name] = parsed_json[prop_name]
                            matched += 1
                    if matched > 0:
                        return generated_arguments, True
                else:
                    return parsed_json, True
        except Exception:
            pass
        return {}, False

    def _generate_value_for_schema(self, fdp: atheris.FuzzedDataProvider, schema: dict, param_name: str = "", sig = None) -> any:
        """Recursively generates valid schema-conforming data values using FuzzedDataProvider."""
        if "enum" in schema and schema["enum"]:
            idx = fdp.ConsumeIntInRange(0, len(schema["enum"]) - 1)
            return schema["enum"][idx]

        is_bytes = self._is_bytes_parameter(param_name, sig) or (param_name in self.file_backed_params)
        if is_bytes:
            return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048))

        prop_type = schema.get("type")
        if prop_type == "string":
            return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 300))
        elif prop_type == "integer":
            return fdp.ConsumeInt(4)
        elif prop_type == "number":
            return fdp.ConsumeFloat()
        elif prop_type == "boolean":
            return fdp.ConsumeBool()
        elif prop_type == "array":
            items_schema = schema.get("items", {})
            count = fdp.ConsumeIntInRange(0, 5)
            return [self._generate_value_for_schema(fdp, items_schema, param_name, sig) for _ in range(count)]
        elif prop_type == "object":
            sub_props = schema.get("properties", {})
            obj = {}
            for sub_name, sub_schema in sub_props.items():
                obj[sub_name] = self._generate_value_for_schema(fdp, sub_schema, sub_name, sig)
            return obj
        else:
            return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))

    def _generate_fallback_inputs(self, data: bytes, properties: dict, sig) -> dict:
        """Generates random schema-conforming inputs using FuzzedDataProvider."""
        fdp = atheris.FuzzedDataProvider(data)
        generated_arguments = {}
        for prop_name, prop_attrs in properties.items():
            generated_arguments[prop_name] = self._generate_value_for_schema(fdp, prop_attrs, prop_name, sig)
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
