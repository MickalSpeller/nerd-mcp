"""Authorized query and write boundaries over the baseline workflow."""

from __future__ import annotations

from .policy import BaselineWriteAuthorization, BaselineWritePolicy


class BaselineQueryService:
    """Expose baseline reads and comparisons without baseline mutation methods."""

    def __init__(self, baselines):
        self._baselines = baselines

    def list(self):
        return self._baselines.list()

    def get_full(self, device):
        return self._baselines.get_full(device)

    def get_page(self, device, cursor, revision):
        return self._baselines.get_page(device, cursor, revision)

    def status(self, max_age_days):
        return self._baselines.status(max_age_days)

    def compare_full(self, device):
        return self._baselines.compare_full(device)

    def compare_all(self, workers):
        return self._baselines.compare_all(workers)

    def compare_page(self, device, cursor, revision):
        return self._baselines.compare_page(device, cursor, revision)


class BaselineWriteService:
    def __init__(self, inventory, baselines, policy: BaselineWritePolicy | None = None):
        self.inventory = inventory
        self._baselines = baselines
        self.policy = policy or BaselineWritePolicy()

    def authorize_capture(self, device: str, source: str = "running",
                          replace: bool = False) -> BaselineWriteAuthorization:
        return self.policy.authorize(
            "capture_configuration_baseline", (device,),
            source=source, replace=replace,
        )

    def authorize_capture_all(self, source: str = "running") -> BaselineWriteAuthorization:
        return self.policy.authorize(
            "capture_configuration_baseline",
            (device.name for device in self.inventory.list()),
            source=source, replace=False,
        )

    def authorize_refresh_all(self, source: str | None = None) -> BaselineWriteAuthorization:
        return self.policy.authorize(
            "refresh_configuration_baselines",
            (device.name for device in self.inventory.list()),
            source=source, replace=True,
        )

    def authorize_remove(self, device: str) -> BaselineWriteAuthorization:
        return self.policy.authorize(
            "remove_configuration_baseline", (device,),
            source=None, replace=False,
        )

    def capture(self, device: str, source: str = "running", replace: bool = False, *,
                authorization: BaselineWriteAuthorization) -> dict[str, object]:
        self.policy.require(
            authorization, "capture_configuration_baseline", (device,),
            source=source, replace=replace,
        )
        return self._baselines.capture(device, source, replace)

    def capture_all(self, source: str = "running", workers: int = 4, *,
                    authorization: BaselineWriteAuthorization) -> dict[str, object]:
        devices = tuple(device.name for device in self.inventory.list())
        self.policy.require(
            authorization, "capture_configuration_baseline", devices,
            source=source, replace=False,
        )
        return self._baselines.capture_all(source, workers)

    def refresh_all(self, source: str | None = None, workers: int = 4, *,
                    authorization: BaselineWriteAuthorization) -> dict[str, object]:
        devices = tuple(device.name for device in self.inventory.list())
        self.policy.require(
            authorization, "refresh_configuration_baselines", devices,
            source=source, replace=True,
        )
        return self._baselines.refresh_all(source, workers)

    def remove(self, device: str, *, authorization: BaselineWriteAuthorization) -> bool:
        self.policy.require(
            authorization, "remove_configuration_baseline", (device,),
            source=None, replace=False,
        )
        return self._baselines.remove(device)
