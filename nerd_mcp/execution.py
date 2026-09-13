"""Per-query execution provenance and timing."""

from dataclasses import dataclass, field
from time import perf_counter

from .application.operations import OperationSource, operation, operation_names
from .domain.provenance import OperationProvenance

LOCAL_INVENTORY_TOOLS = operation_names(
    source=OperationSource.LOCAL_INVENTORY, mcp_only=True
)
LIVE_DEVICE_TOOLS = operation_names(
    source=OperationSource.LIVE_DEVICE, mcp_only=True
)


@dataclass
class ExecutionTrace:
    started_at: float = field(default_factory=perf_counter)
    finished_at: float | None = None
    llm_used: bool = False
    llm_model: str | None = None
    llm_calls: int = 0
    provenance: OperationProvenance = field(default_factory=OperationProvenance)
    path: str | None = None
    planning_seconds: float = 0.0
    mcp_seconds: float = 0.0
    llm_seconds: float = 0.0
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0

    def finish(self) -> None:
        if self.finished_at is None:
            self.finished_at = perf_counter()

    @property
    def elapsed_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else perf_counter()
        return max(0.0, end - self.started_at)

    @property
    def mcp_used(self) -> bool:
        return bool(self.mcp_tools)

    @property
    def mcp_tools(self) -> list[str]:
        return self.provenance.operations

    @property
    def local_inventory_used(self) -> bool:
        return self.provenance.local_inventory_used

    @local_inventory_used.setter
    def local_inventory_used(self, value: bool) -> None:
        self.provenance.local_inventory_used = value

    @property
    def live_ssh_used(self) -> bool:
        return self.provenance.live_ssh_used

    @live_ssh_used.setter
    def live_ssh_used(self, value: bool) -> None:
        self.provenance.live_ssh_used = value

    @property
    def mock_used(self) -> bool:
        return self.provenance.mock_used

    @mock_used.setter
    def mock_used(self, value: bool) -> None:
        self.provenance.mock_used = value

    @property
    def local_system_used(self) -> bool:
        return self.provenance.local_system_used

    @local_system_used.setter
    def local_system_used(self, value: bool) -> None:
        self.provenance.local_system_used = value

    @staticmethod
    def _usage_value(value, name: str, default=0):
        if value is None:
            return default
        if isinstance(value, dict):
            return value.get(name, default)
        return getattr(value, name, default)

    def record_llm(self, model: str | None, elapsed_seconds: float = 0.0, usage=None) -> None:
        self.llm_used = True
        self.llm_calls += 1
        self.llm_seconds += max(0.0, elapsed_seconds)
        if model:
            self.llm_model = model
        self.input_tokens += int(self._usage_value(usage, "input_tokens") or 0)
        self.output_tokens += int(self._usage_value(usage, "output_tokens") or 0)
        input_details = self._usage_value(usage, "input_tokens_details", {})
        output_details = self._usage_value(usage, "output_tokens_details", {})
        self.cached_input_tokens += int(self._usage_value(input_details, "cached_tokens") or 0)
        self.reasoning_tokens += int(self._usage_value(output_details, "reasoning_tokens") or 0)

    def record_tool(self, name: str, mock: bool = False, successful: bool = True,
                    elapsed_seconds: float = 0.0) -> None:
        self.mcp_seconds += max(0.0, elapsed_seconds)
        try:
            sources = operation(name).sources
        except KeyError:
            sources = frozenset()
        self.provenance.record(
            name,
            local_inventory=OperationSource.LOCAL_INVENTORY in sources,
            live_device=OperationSource.LIVE_DEVICE in sources,
            mock=mock,
            successful=successful,
        )

    def data_sources(self) -> list[str]:
        return self.provenance.data_sources(self.llm_used)
