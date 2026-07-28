import json
import logging
import os
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
    from langchain_core.tools import tool
except ImportError:
    ChatOpenAI = None
    HumanMessage = SystemMessage = ToolMessage = None
    def tool(func):
        return func


from . import seed_generators

logger = logging.getLogger(__name__)


@tool
def create_pdf(content: str, filename: str) -> str:
    """
    Creates a valid PDF document with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_pdf(content, filename)


@tool
def create_docx(content: str, filename: str) -> str:
    """
    Creates a valid Word (DOCX) document with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_docx(content, filename)


@tool
def create_xlsx(sheet_data: list, filename: str) -> str:
    """
    Creates a valid Excel (XLSX) spreadsheet with the specified table data and saves it.
    sheet_data is a list of rows, where each row is a list of cell values.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_xlsx(sheet_data, filename)


@tool
def create_pptx(content: str, filename: str) -> str:
    """
    Creates a valid PowerPoint (PPTX) presentation with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_pptx(content, filename)


@tool
def create_zip(files: dict, filename: str) -> str:
    """
    Creates a valid ZIP archive containing the specified file names and their text contents and saves it.
    files is a dictionary mapping sub-filename to its text content.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_zip(files, filename)


@tool
def create_xml(xml_content: str, filename: str) -> str:
    """
    Creates a valid XML file with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_xml(xml_content, filename)


@tool
def create_html(html_content: str, filename: str) -> str:
    """
    Creates a valid HTML file with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_html(html_content, filename)


@tool
def create_json(json_content: str, filename: str) -> str:
    """
    Creates a valid JSON file with the specified content and saves it.
    Returns the reference format: 'predefined_seed:<filename>'
    """
    return seed_generators.create_json(json_content, filename)



class LLMHandler:
    def __init__(self, api_key: str, model_name: str = "minimax-m3:cloud", base_url: str = "https://ollama.com/v1"):
        self.model = ChatOpenAI(api_key=api_key, base_url=base_url, model=model_name, timeout=15, max_retries=0)

    def _load_seed_bank(self) -> dict:
        """Loads all JSON files from src/seed_bank/ into a dictionary."""
        seed_bank = {}
        bank_dir = os.path.join(os.path.dirname(__file__), "seed_bank")
        if not os.path.exists(bank_dir):
            return seed_bank
            
        for file in os.listdir(bank_dir):
            if file.endswith(".json"):
                try:
                    with open(os.path.join(bank_dir, file), "r") as f:
                        data = json.load(f)
                    category = data.get("category")
                    if category:
                        seed_bank[category] = {
                            "description": data.get("description", ""),
                            "payloads": data.get("payloads", [])
                        }
                except Exception as e:
                    logging.warning(f"Failed to load seed bank file {file}: {e}")
        return seed_bank

    def _local_fallback_mapping(self, input_schema: dict, seed_bank: dict) -> list:
        """Generates fuzzing seeds locally without LLM API supporting type fuzzing and type confusion."""
        logging.info("[Seed Gen] Using local fallback mapping mechanism with multi-type fuzzing...")
        properties = input_schema.get("properties", {})
        
        # 1. Map properties to default values based on type
        defaults = {}
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            if p_type in ("integer", "number"):
                defaults[prop] = 1
            elif p_type == "boolean":
                defaults[prop] = True
            elif p_type == "array":
                defaults[prop] = []
            elif p_type == "object":
                defaults[prop] = {}
            else:
                defaults[prop] = "test"
                
        seeds = []
        
        # 2. Generate type-specific boundary values
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            
            if p_type in ("integer", "number"):
                # JSON-compliant boundary numbers
                boundaries = [0, -1, 2147483647, -2147483648, 1e308, -1e308, None]
                for val in boundaries:
                    seed = defaults.copy()
                    seed[prop] = val
                    seeds.append(seed)
            elif p_type == "boolean":
                # Alternate boolean values
                for val in [True, False]:
                    seed = defaults.copy()
                    seed[prop] = val
                    seeds.append(seed)
            elif p_type == "array":
                # Array boundaries and malformations
                variations = [
                    [],
                    [None],
                    ["test"],
                    [1, 2, 3],
                    ["text", 123, None, {}]
                ]
                for val in variations:
                    seed = defaults.copy()
                    seed[prop] = val
                    seeds.append(seed)
            elif p_type == "object":
                # Object boundaries
                variations = [
                    {},
                    {"nested": "val"},
                    {"depth1": {"depth2": {"depth3": "deep"}}}
                ]
                for val in variations:
                    seed = defaults.copy()
                    seed[prop] = val
                    seeds.append(seed)
            elif p_type == "string":
                # Check keywords and inject from seed bank
                prop_lower = prop.lower()
                desc_lower = attrs.get("description", "").lower()
                
                category_to_use = None
                if "sql" in prop_lower or "query" in prop_lower or "sql" in desc_lower or "query" in desc_lower:
                    category_to_use = "sql_injection"
                elif "url" in prop_lower or "uri" in prop_lower or "link" in prop_lower or "url" in desc_lower or "uri" in desc_lower or "link" in desc_lower:
                    category_to_use = "ssrf_url"
                elif "path" in prop_lower or "file" in prop_lower or "dir" in prop_lower or "path" in desc_lower or "file" in desc_lower or "dir" in desc_lower:
                    category_to_use = "path_traversal"
                elif "pattern" in prop_lower or "search" in prop_lower or "like" in prop_lower or "pattern" in desc_lower or "search" in desc_lower or "like" in desc_lower:
                    category_to_use = "wildcards"
                elif "html" in prop_lower or "xml" in prop_lower or "xml" in desc_lower or "html" in desc_lower or "markdown" in desc_lower:
                    category_to_use = "xss_markdown"
                    
                if category_to_use and category_to_use in seed_bank:
                    category_data = seed_bank[category_to_use]
                    for payload in category_data["payloads"][:5]:
                        seed = defaults.copy()
                        seed[prop] = payload
                        seeds.append(seed)
                else:
                    # Fallback string injections
                    for cat in ["path_traversal", "sql_injection"]:
                        if cat in seed_bank:
                            for payload in seed_bank[cat]["payloads"][:2]:
                                seed = defaults.copy()
                                seed[prop] = payload
                                seeds.append(seed)
                                
        # 3. Generate Type Confusion seeds (deliberate type mismatches)
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            
            confusion_vals = []
            if p_type == "string":
                confusion_vals = [123, True, ["not_a_string"]]
            elif p_type in ("integer", "number"):
                confusion_vals = ["not_a_number", [1]]
            elif p_type == "boolean":
                confusion_vals = ["true", 1]
            elif p_type in ("array", "object"):
                confusion_vals = ["not_a_structure", 99]
                
            for val in confusion_vals:
                seed = defaults.copy()
                seed[prop] = val
                seeds.append(seed)

        # Add basic clean defaults
        seeds.append(defaults)
        
        # Deduplicate seeds
        unique_seeds = []
        seen = []
        for s in seeds:
            s_str = json.dumps(s, sort_keys=True)
            if s_str not in seen:
                seen.append(s_str)
                unique_seeds.append(s)
                
        return unique_seeds

    def generate_seeds(self, tool_name: str, tool_description: str, input_schema: dict) -> list:
        """Generate fuzzing seeds by letting the LLM select and adapt payloads from a seed bank."""
        logging.info(f"[LLM] Generation of smart seed corpus for '{tool_name}' using Seed Bank...")
        
        seed_bank = self._load_seed_bank()
        if not seed_bank:
            logging.warning("Seed bank is empty or not found. Falling back to local mapping.")
            return self._local_fallback_mapping(input_schema, {})
            
        example_structure = {}
        properties = input_schema.get("properties", {})
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            example_structure[prop] = f"<{p_type}>"
            
        # Format the seed bank categories for the prompt
        seed_bank_desc = ""
        for cat, data in seed_bank.items():
            seed_bank_desc += f"- Category: '{cat}'\n  Description: {data['description']}\n  Sample Payloads: {json.dumps(data['payloads'][:3])}\n\n"
            
        prompt = f"""
You are a security and QA engineering expert. You will generate a JSON array of test cases (inputs) to fuzz the following tool.

Tool Name: {tool_name}
Description: {tool_description}
Schema Contract: {input_schema}

We have a structured Seed Bank containing pre-curated payloads categorized by attack vectors:
{seed_bank_desc}

We also have predefined file generator tools that you can call to create valid binary/text files:
- create_pdf
- create_docx
- create_xlsx
- create_pptx
- create_zip
- create_xml
- create_html
- create_json

You should call these file generator tools if you want to test the tool with high-quality custom documents. Each tool will save the file and return a string like "predefined_seed:<filename>".
Use the exact returned string as the value for the file/URI parameter in the test case.

Strict Instructions:
1. Select the relevant Seed Bank categories for fuzzing this tool.
2. Adapt the payloads from those selected categories into the parameters of the tool schema.
3. For non-string parameters:
   - For integers/numbers, include test cases with boundary values (e.g. 0, -1, large numbers).
   - For arrays, include empty arrays [] and heterogeneous/malformed arrays.
   - For booleans, test both true and false.
4. Intentionally include a few type confusion/type mismatch test cases (e.g., passing a string to an integer, or an array to a string parameter) to check type-handling robustness.
5. Every object in the array MUST strictly follow this argument structure: {json.dumps(example_structure)}
6. Return ONLY a valid raw JSON array containing 6 to 12 objects. No explanations, no markdown blocks. Just plain raw JSON.
"""
        messages = [HumanMessage(content=prompt)]
        
        tools = [
            create_pdf,
            create_docx,
            create_xlsx,
            create_pptx,
            create_zip,
            create_xml,
            create_html,
            create_json
        ]
        tools_map = {t.name: t for t in tools}
        model_with_tools = self.model.bind_tools(tools)
        
        max_attempts = 4
        attempt = 1
        
        while attempt <= max_attempts:
            try:
                response = model_with_tools.invoke(messages)
                messages.append(response)
                
                if response.tool_calls:
                    for tool_call in response.tool_calls:
                        t_name = tool_call["name"]
                        t_args = tool_call["args"]
                        t_id = tool_call["id"]
                        
                        logging.info(f"[LLM Seed Gen Tool Call] Invoking {t_name} with {t_args}")
                        if t_name in tools_map:
                            try:
                                result = tools_map[t_name].invoke(t_args)
                            except Exception as e:
                                result = f"Error running tool {t_name}: {e}"
                        else:
                            result = f"Error: Tool {t_name} not found."
                        
                        logging.info(f"[LLM Seed Gen Tool Call] Result: {result}")
                        messages.append(ToolMessage(content=result, tool_call_id=t_id))
                    continue
                
                content = response.content.strip().strip("```json").strip("```").strip()
                if not content:
                    messages.append(HumanMessage(content="Please provide the final raw JSON array of test cases now."))
                    attempt += 1
                    continue
                
                parsed_seeds = json.loads(content)
                if not isinstance(parsed_seeds, list):
                    raise ValueError("The LLM returned a JSON object but a JSON ARRAY (list) of objects was expected.")
                
                return parsed_seeds
                
            except Exception as e:
                logging.warning(f"Seed generation attempt {attempt} failed ({e}).")
                if attempt == max_attempts:
                    break
                messages.append(HumanMessage(content=f"Your previous output was invalid: {str(e)}. Please correct it and output ONLY the valid raw JSON array."))
                attempt += 1
                
        # Trigger local fallback mapping if LLM failed
        return self._local_fallback_mapping(input_schema, seed_bank)



    def select_sanitizers(self, tool_name: str, tool_description: str, input_schema: dict, available_sanitizers: dict) -> tuple:
        """Selects sanitizing functions and their behavioral rules based on docstrings/schemas."""
        logging.info(f"Selecting relevant sanitizers for '{tool_name}'...")
        
        sanitizers_format = "\n".join([f"- {name}: {desc}" for name, desc in available_sanitizers.items()])

        prompt = f"""
You are an expert security engineer. Analyze the following tool metadata and select which sanitizers from the provided list are relevant to monitor its inputs. Also, analyze the tool description and docstring to determine what the tool's expected behavior is if a sanitizer triggers.

Tool Name: {tool_name}
Description: {tool_description}
Schema: {input_schema}

Available Sanitizers:
{sanitizers_format}

Strict Instructions:
1. Return ONLY a valid JSON object with two keys:
   - "selected_sanitizers": A JSON array of strings containing the exact names of the selected sanitizers.
   - "rules": A JSON object mapping a selected sanitizer name to its expected behavior rule:
     {{
       "sanitizer_name": {{
         "on_trigger": "allow_success_always" or "allow_success_with_fallback" or "raise_exception",
         "expected_fallback_values": [<expected return values when sanitizer is triggered, e.g. [], "", null, etc.>]
       }}
     }}
     Use "allow_success_always" if the tool is designed to process arbitrary text that might contain invalid elements (like a JSON extractor or lenient parser) and should always succeed normally with any output.
     Use "allow_success_with_fallback" if the tool expects a specific valid structure but gracefully returns a fallback value when invalid.
     Use "raise_exception" if the tool should strictly raise an exception/error on invalid input.
2. If no sanitizers are relevant, return: {{"selected_sanitizers": [], "rules": {{}}}}
3. No code blocks, no markdown formatting. Just raw JSON.
"""
        messages = [HumanMessage(content=prompt)]
        
        try:
            response = self.model.invoke(messages)
            content = response.content.strip().strip("```json").strip("```").strip()
            logging.info(response.content)
            data = json.loads(content)
            selected = data.get("selected_sanitizers", [])
            rules = data.get("rules", {})
            if isinstance(selected, list) and isinstance(rules, dict):
                valid_selection = [s for s in selected if s in available_sanitizers]
                valid_rules = {s: r for s, r in rules.items() if s in valid_selection}
                logging.info(f"Sanitizers selected: {valid_selection}")
                logging.info(f"Sanitizer rules: {valid_rules}")
                return valid_selection, valid_rules
        except Exception as e:
            logging.warning(f"Failed to parse LLM sanitizer selection: {e}. Defaulting to empty list and rules.")
        
        return [], {}
