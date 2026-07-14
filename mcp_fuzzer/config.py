from dataclasses import dataclass, field

@dataclass
class FuzzerConfig:
    timeout_limit: float = 2.0
    unexpected_crashes: tuple[str, ...] = (
        "AttributeError",
        "IndexError",
        "TypeError",
        "KeyError",
        "RecursionError",
        "ZeroDivisionError",
        "NameError",
        "UnboundLocalError"
    )
    dependencies_to_instrument: list[str] = field(default_factory=lambda: [
        "pypdf",
        "openpyxl",
        "mammoth",
        "pptx",
        "bs4",
        "jinja2"
    ])
