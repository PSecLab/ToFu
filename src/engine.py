import sys
import os
import logging
import threading
import atheris

logger = logging.getLogger(__name__)


class AtherisFuzzingEngine:
    """Boundary adapter wrapping the external Atheris/LibFuzzer framework with metric stream interception."""

    def __init__(
        self,
        corpus_dir: str,
        time_per_iteration: int,
        dict_file: str = None,
        metrics_collector=None,
        pulse_interval: int = 2,
    ):
        self.corpus_dir = corpus_dir
        self.time_per_iteration = time_per_iteration
        self.dict_file = dict_file
        self.metrics_collector = metrics_collector
        self.pulse_interval = pulse_interval

    def fuzz(self, callback) -> None:
        """Starts the LibFuzzer guided loop with the provided entry point callback."""
        atheris_args = [
            sys.argv[0],
            f"-max_total_time={self.time_per_iteration}",
            "-artifact_prefix=/tmp/",
        ]
        if self.pulse_interval and self.pulse_interval > 0:
            atheris_args.append(f"-pulse={self.pulse_interval}")
        if self.dict_file:
            atheris_args.append(f"-dict={self.dict_file}")
        atheris_args.append(self.corpus_dir)
        atheris.Setup(atheris_args, callback)

        if self.metrics_collector:
            self._fuzz_with_interception()
        else:
            try:
                atheris.Fuzz()
            except SystemExit:
                pass
            except Exception as e:
                logger.error(f"Error during Atheris execution: {e}")

    def _fuzz_with_interception(self) -> None:
        """Intercepts C-level stderr stream to extract LibFuzzer coverage metrics without blocking output."""
        r_fd, w_fd = os.pipe()
        saved_stderr_fd = os.dup(2)
        reader_thread = None

        def _reader():
            with os.fdopen(r_fd, "r", encoding="utf-8", errors="replace") as pipe_reader:
                for line in pipe_reader:
                    # Echo line back to real stderr
                    try:
                        os.write(saved_stderr_fd, line.encode("utf-8", errors="replace"))
                    except Exception:
                        pass
                    # Parse metric line
                    if self.metrics_collector:
                        try:
                            self.metrics_collector.parse_libfuzzer_line(line)
                        except Exception as err:
                            logger.debug(f"Metrics parsing error: {err}")

        try:
            sys.stderr.flush()
            os.dup2(w_fd, 2)
            os.close(w_fd)
            reader_thread = threading.Thread(target=_reader, daemon=True)
            reader_thread.start()

            try:
                atheris.Fuzz()
            except SystemExit:
                pass
            except Exception as e:
                logger.error(f"Error during Atheris execution: {e}")

        finally:
            try:
                sys.stderr.flush()
            except Exception:
                pass
            os.dup2(saved_stderr_fd, 2)
            os.close(saved_stderr_fd)
            if reader_thread and reader_thread.is_alive():
                reader_thread.join(timeout=1.0)
