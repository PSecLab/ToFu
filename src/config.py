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
    allowed_workspace_dir: str = None
    # Working directory for the TARGET process. prepare_targets.py records this
    # per repo; before bug 21 nothing read it, so every target inherited ToFu's
    # own cwd (the repo root) and relative paths resolved against OUR tree.
    target_cwd: str = None
    # Per-target environment overrides from the config's "env" field. Used to
    # hand credential-gated servers PLACEHOLDER values so they get past import-
    # time presence checks (e.g. GOOGLE_API_KEY: ['Required']) and expose their
    # tools. Never real secrets: see prepare_targets.TARGET_ENV_HINTS.
    target_env: dict = None
    enable_metrics: bool = True
    metrics_dir: str = "metrics"
    metrics_pulse_interval: int = 2
    metrics_sample_interval_sec: float = 60.0
    export_csv: bool = True
    export_mongo: bool = False
