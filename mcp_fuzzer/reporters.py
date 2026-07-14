import abc
import json
import logging
import time
from pymongo import MongoClient

logger = logging.getLogger(__name__)

class BaseVulnerabilityReporter(abc.ABC):
    """Abstract base class for vulnerability reporting."""
    @abc.abstractmethod
    def report(self, tool_name: str, inputs: dict, output: any, triggered_sanitizers: list[str], analysis: str) -> None:
        pass

class MongoVulnerabilityReporter(BaseVulnerabilityReporter):
    """Logs vulnerability details to a MongoDB database."""
    def __init__(self, connection_uri: str = "mongodb://localhost:27017/", database_name: str = "toolfuzz_db", collection_name: str = "vulnerabilities"):
        self.connection_uri = connection_uri
        self.database_name = database_name
        self.collection_name = collection_name
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = MongoClient(self.connection_uri, serverSelectionTimeoutMS=2000)
        return self._client

    def report(self, tool_name: str, inputs: dict, output: any, triggered_sanitizers: list[str], analysis: str) -> None:
        try:
            def default_serializer(o):
                if isinstance(o, bytes):
                    return o.decode('utf-8', errors='replace')
                return repr(o)

            try:
                input_str = json.dumps(inputs, default=default_serializer)
            except Exception:
                input_str = str(inputs)

            client = self._get_client()
            db = client[self.database_name]
            collection = db[self.collection_name]
            document = {
                "tool": tool_name,
                "input": input_str,
                "output": output,
                "triggered_sanitizers": triggered_sanitizers,
                "timestamp": time.time(),
                "analysis": analysis
            }
            collection.insert_one(document)
            logger.info(f"[MongoDB] Vulnerability successfully logged to {self.database_name}.{self.collection_name}.")
        except Exception as mongo_err:
            logger.error(f"[MongoDB] Failed to log vulnerability to database: {mongo_err}")

class ConsoleVulnerabilityReporter(BaseVulnerabilityReporter):
    """Logs vulnerability details directly to logger/stdout."""
    def report(self, tool_name: str, inputs: dict, output: any, triggered_sanitizers: list[str], analysis: str) -> None:
        logger.warning(f"\n[POTENTIAL VULNERABILITY / BUG FOUND] in '{tool_name}' !")
        logger.warning(f"   -> Faulty Input : {repr(inputs)}")
        logger.warning(f"   -> Tool Output  : {repr(output)}")
        logger.warning(f"   -> Analysis     : {analysis}")
        logger.warning(f"   -> Triggered Sanitizers : {triggered_sanitizers}")

class CompositeVulnerabilityReporter(BaseVulnerabilityReporter):
    """Dispatches reports to multiple sub-reporters."""
    def __init__(self, reporters: list[BaseVulnerabilityReporter]):
        self.reporters = reporters

    def report(self, tool_name: str, inputs: dict, output: any, triggered_sanitizers: list[str], analysis: str) -> None:
        for r in self.reporters:
            try:
                r.report(tool_name, inputs, output, triggered_sanitizers, analysis)
            except Exception as e:
                logger.error(f"Error executing sub-reporter {r.__class__.__name__}: {e}")
