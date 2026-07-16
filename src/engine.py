import sys
import logging
import atheris

logger = logging.getLogger(__name__)

class AtherisFuzzingEngine:
    """Boundary adapter wrapping the external Atheris/LibFuzzer framework."""
    def __init__(self, corpus_dir: str, time_per_iteration: int):
        self.corpus_dir = corpus_dir
        self.time_per_iteration = time_per_iteration

    def fuzz(self, callback) -> None:
        """Starts the LibFuzzer guided loop with the provided entry point callback."""
        atheris_args = [
            sys.argv[0],
            f"-max_total_time={self.time_per_iteration}",
            "-artifact_prefix=/tmp/",
            self.corpus_dir
        ]
        atheris.Setup(atheris_args, callback)
        try:
            atheris.Fuzz()
        except SystemExit:
            pass
        except Exception as e:
            logger.error(f"Error during Atheris execution: {e}")
