import json
import logging
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from mcp_fuzzer import seed_generators

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
        self.model = ChatOpenAI(api_key=api_key, base_url=base_url, model=model_name, timeout=15)

    def generate_seeds(self, tool_name: str, tool_description: str, input_schema: dict) -> list:
        """Generate fuzzing seeds"""
        logging.info(f"[LLM] Generation of smart seed corpus for '{tool_name}'...")
        
        example_structure = {}
        properties = input_schema.get("properties", {})
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            example_structure[prop] = f"<{p_type}>"

        prompt = f"""
You are a security and QA engineering expert. Generate a JSON array containing relevant test cases (inputs) to fuzz the following tool.
Provide a mix of perfectly valid inputs, boundary edge cases, and malicious payloads (e.g., injections, bad types, empty data).

Tool Name: {tool_name}
Description: {tool_description}
Schema Contract: {input_schema}

We have predefined/generator functions that you can choose to call to create custom, valid binary/text files for any parameter that expects a URI, path, or file content:
- create_pdf
- create_docx
- create_xlsx
- create_pptx
- create_zip
- create_xml
- create_html
- create_json

You should call these tools if you want to test the tool with high-quality custom documents. Each tool will save the file and return a string in the format "predefined_seed:<filename>".
Use the exact returned string (e.g. "predefined_seed:your_generated_file.pdf") as the value for the file/URI parameter in the test case.

Strict Instructions:
1. Return ONLY a valid raw JSON array containing 5 to 10 objects. Each object represents arguments to pass to the tool.
2. Every object in the array MUST strictly follow this argument structure: {json.dumps(example_structure)}
3. If an argument schema description specifies a format (like a JSON string, a list, or an object), make sure some test cases provide valid structures, and others provide broken/malicious structures.
4. You are encouraged to call the creation tools and use the returned "predefined_seed:<filename>" strings for URI/path/file parameters in your test cases.
5. No explanations, no markdown blocks (no backticks). Just plain raw JSON.
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
        
        max_attempts = 8
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
                    # Model only called tools, prompt it for the final JSON response
                    messages.append(HumanMessage(content="Please provide the final raw JSON array of test cases now."))
                    attempt += 1
                    continue
                
                # Validate JSON format
                parsed_seeds = json.loads(content)
                if not isinstance(parsed_seeds, list):
                    raise ValueError("The LLM returned a JSON object but a JSON ARRAY (list) of objects was expected.")
                
                return parsed_seeds

            except Exception as e:
                logging.warning(f"Seed generation attempt {attempt} failed ({e}).")
                
                if attempt == max_attempts:
                    logging.warning("Max refinement attempts reached for seeds. Using minimal fallback.")
                    break
                
                # Append failed context
                messages.append(HumanMessage(content=f"""
Your previous output was invalid and failed with this error: {str(e)}
Please rewrite your response to ensure it is 100% valid, raw JSON array matching the schema without any extra text or syntax errors.
"""))
                attempt += 1

        # Fallback if API unreachable
        fallback_seed = {}
        for prop, attrs in properties.items():
            p_type = attrs.get("type")
            if p_type == "string":
                fallback_seed[prop] = "test_string"
            elif p_type == "integer":
                fallback_seed[prop] = 1
            elif p_type == "boolean":
                fallback_seed[prop] = True
        return [fallback_seed, {}]



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
