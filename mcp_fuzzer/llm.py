import json
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import logging
logger = logging.getLogger(__name__)


class LLMHandler:
    def __init__(self, api_key: str, model_name: str = "minimax-m3:cloud", base_url: str = "https://ollama.com/v1"):
        self.model = ChatOpenAI(api_key=api_key, base_url=base_url, model=model_name)

    def generate_seeds(self, tool_name: str, tool_description: str, input_schema: dict) -> list:
        """Generate fuzzing seeds"""
        logging.info(f"[LLM] Generation of smart seed corpus for '{tool_name}'...")
        
        example_structure = {}
        properties = input_schema.get("properties", {})
        for prop, attrs in properties.items():
            p_type = attrs.get("type", "string")
            example_structure[prop] = f"<{p_type}>"

        # Initial prompt
        prompt = f"""
You are a security and QA engineering expert. Generate a JSON array containing relevant test cases (inputs) to fuzz the following tool.
Provide a mix of perfectly valid inputs, boundary edge cases, and malicious payloads (e.g., injections, bad types, empty data).

Tool Name: {tool_name}
Description: {tool_description}
Schema Contract: {input_schema}

Strict Instructions:
1. Return ONLY a valid raw JSON array containing 5 to 10 objects. Each object represents arguments to pass to the tool.
2. Every object in the array MUST strictly follow this argument structure: {json.dumps(example_structure)}
3. If an argument schema description specifies a format (like a JSON string, a list, or an object), make sure some test cases provide valid structures, and others provide broken/malicious structures.
4. No explanations, no markdown blocks (no backticks). Just plain raw JSON.
"""
        messages = [HumanMessage(content=prompt)]
        
        max_attempts = 3
        attempt = 1
        
        while attempt <= max_attempts:
            try:
                if attempt > 1:
                    logging.info(f"Self-Refining seeds generation (Attempt {attempt}/{max_attempts})...")
                
                response = self.model.invoke(messages)
                content = response.content.strip().strip("```json").strip("```").strip()
                
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



    def select_sanitizers(self, tool_name: str, tool_description: str, input_schema: dict, available_sanitizers: dict) -> list:
        """Selects sanitizing functions based on docstrings."""
        logging.info(f"Selecting relevant sanitizers for '{tool_name}'...")
        
        sanitizers_format = "\n".join([f"- {name}: {desc}" for name, desc in available_sanitizers.items()])

        prompt = f"""
You are an expert security engineer. Analyze the following tool metadata and select which sanitizers from the provided list are relevant to monitor its inputs.

Tool Name: {tool_name}
Description: {tool_description}
Schema: {input_schema}

Available Sanitizers:
{sanitizers_format}

Strict Instructions:
1. Return ONLY a valid JSON array of strings containing the exact names of the selected sanitizers.
2. If no sanitizers are relevant, return an empty array [].
3. No code blocks, no markdown formatting. Just raw JSON.
"""
        messages = [HumanMessage(content=prompt)]
        
        try:
            response = self.model.invoke(messages)
            content = response.content.strip().strip("```json").strip("```").strip()
            logging.info(response.content)
            selected = json.loads(content)
            if isinstance(selected, list): # Avoid hallucinated functions
                valid_selection = [s for s in selected if s in available_sanitizers]
                logging.info(f"Sanitizers selected: {valid_selection}")
                return valid_selection
        except Exception as e:
            logging.warning(response.content)
            logging.warning(f"Failed to parse LLM sanitizer selection: {e}. Defaulting to empty list.")
        
        return []
