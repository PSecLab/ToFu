import abc

class BaseMetadataProvider(abc.ABC):
    """Abstract interface defining the contract for discovering targets and retrieving metadata."""
    
    @abc.abstractmethod
    async def fetch_all_tools(self) -> list[str]:
        """Discovers and returns a list of target names."""
        pass

    @abc.abstractmethod
    async def fetch_tool_metadata(self, tool_name: str) -> tuple[str, str, dict]:
        """
        Retrieves schema/documentation metadata for the specified target.
        Returns a tuple: (name, description, schema_dict)
        """
        pass
