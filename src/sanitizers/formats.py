import re
import xml.parsers.expat

def check_xml_xxe(value: str) -> bool:
    if not isinstance(value, str):
        return False
    is_xxe = [False]
    def doctype_handler(name, sysid, pubid, has_internal_subset):
        if sysid or pubid:
            is_xxe[0] = True
    def entity_decl_handler(entityName, is_parameter_entity, val, base, systemId, publicId, notationName):
        if systemId or publicId:
            is_xxe[0] = True

    parser = xml.parsers.expat.ParserCreate()
    parser.StartDoctypeDeclHandler = doctype_handler
    parser.EntityDeclHandler = entity_decl_handler
    try:
        parser.Parse(value)
    except Exception:
        pass
    return is_xxe[0]

def check_xml_bomb(value: str) -> bool:
    if not isinstance(value, str):
        return False
    is_bomb = [False]
    entity_count = [0]
    def entity_decl_handler(entityName, is_parameter_entity, val, base, systemId, publicId, notationName):
        entity_count[0] += 1
        if entity_count[0] > 5 or (val and "&" in val):
            is_bomb[0] = True

    parser = xml.parsers.expat.ParserCreate()
    parser.EntityDeclHandler = entity_decl_handler
    try:
        parser.Parse(value)
    except Exception:
        pass
    return is_bomb[0]

def check_template_injection(value: str) -> bool:
    if not isinstance(value, str):
        return False
    patterns = [
        r'\{\{\s*.*\s*\}\}',    # Jinja2 / Twig / AngularJS
        r'\{%\s*.*\s*%\}',    # Jinja2 / Django
        r'\$\{\s*.*\s*\}',      # JSP / Thymeleaf / ES6 template literal
        r'<\%\s*.*\s*\%>'      # EJS / ERB
    ]
    return any(bool(re.search(p, value)) for p in patterns)
