"""Compatibility exports for the application-owned topology workflow."""

from .application.topology import (
    TopologyWorkflow as _ApplicationTopologyWorkflow,
    _as_ip,
    _identity,
    _observed_time,
    _short_identity,
)
from .domain.ports import InventoryPort, ObservationRepositoryPort
from .mac import MacIndex, MacService
from .topology_rendering import (
    TopologyDiagramPresenter,
    escape_mermaid_text,
    render_mermaid_topology,
    render_text_topology,
)
from .vendors.registry import CAPABILITIES

_diagram_text = escape_mermaid_text


class TopologyWorkflow(_ApplicationTopologyWorkflow):
    """Historical constructor over the application-owned workflow."""

    def __init__(self, inventory: InventoryPort, mock: bool, mac_service,
                 repository: ObservationRepositoryPort,
                 capability_provider=CAPABILITIES):
        super().__init__(
            inventory, mock, mac_service, repository, capability_provider
        )


class TopologyService(TopologyWorkflow):
    """Compatibility facade for historical direct construction."""

    _text_diagram = staticmethod(render_text_topology)
    _mermaid_diagram = staticmethod(render_mermaid_topology)

    def __init__(self, inventory: InventoryPort, mock: bool = False, mac_service=None,
                 repository: ObservationRepositoryPort | None = None):
        super().__init__(
            inventory, mock, mac_service or MacService(inventory, mock),
            repository or MacIndex(inventory),
        )
        self._diagram_presenter = TopologyDiagramPresenter()

    def diagram(self, target: str = "all", location: str = "",
                max_age_minutes: int = 60,
                output_format: str = "text") -> dict[str, object]:
        return self._diagram_presenter.present(
            self.diagram_data(target, location, max_age_minutes), output_format
        )
