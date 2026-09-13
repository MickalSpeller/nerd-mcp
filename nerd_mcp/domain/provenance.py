"""Operational data-source provenance independent of terminal and model timing."""

from dataclasses import dataclass, field


@dataclass
class OperationProvenance:
    operations: list[str] = field(default_factory=list)
    local_inventory_used: bool = False
    live_ssh_used: bool = False
    mock_used: bool = False
    local_system_used: bool = False

    def record(self, name: str, *, local_inventory: bool = False,
               live_device: bool = False, mock: bool = False,
               successful: bool = True) -> None:
        self.operations.append(name)
        if local_inventory:
            self.local_inventory_used = True
        elif live_device and successful:
            if mock:
                self.mock_used = True
            else:
                self.live_ssh_used = True

    def data_sources(self, model_used: bool = False) -> list[str]:
        sources = []
        if self.local_inventory_used:
            sources.append("Local inventory")
        if self.mock_used:
            sources.append("Mock device")
        if self.live_ssh_used:
            sources.append("Live SSH")
        if self.local_system_used:
            sources.append("Local system")
        if not sources:
            sources.append("Conversation context" if model_used else "Local")
        return sources
