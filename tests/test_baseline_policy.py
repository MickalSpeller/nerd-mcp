from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nerd_mcp.application.baselines import BaselineWriteService
from nerd_mcp.application.policy import BaselineAuthorizationError, BaselineWritePolicy


class Inventory:
    def __init__(self, names=("core", "edge")):
        self.names = list(names)

    def list(self):
        return [SimpleNamespace(name=name) for name in self.names]


def make_service(names=("core", "edge")):
    baselines = Mock()
    return BaselineWriteService(Inventory(names), baselines), baselines


def test_single_capture_requires_exact_scoped_authorization():
    service, baselines = make_service()
    authorization = service.authorize_capture("CORE", "running", replace=True)
    baselines.capture.return_value = {"status": "success"}

    assert service.capture(
        "core", "running", replace=True, authorization=authorization
    ) == {"status": "success"}
    baselines.capture.assert_called_once_with("core", "running", True)


@pytest.mark.parametrize("change", ["device", "source", "replace"])
def test_capture_rejects_approval_for_a_different_scope(change):
    service, baselines = make_service()
    authorization = service.authorize_capture("core", "running", replace=False)
    request = {"device": "core", "source": "running", "replace": False}
    request.update({
        "device": {"device": "edge"},
        "source": {"source": "startup"},
        "replace": {"replace": True},
    }[change])

    with pytest.raises(BaselineAuthorizationError, match="does not match"):
        service.capture(**request, authorization=authorization)
    baselines.capture.assert_not_called()


def test_authorization_is_bound_to_its_policy_and_can_be_used_once():
    first, baselines = make_service()
    second = BaselineWriteService(first.inventory, baselines, BaselineWritePolicy())
    authorization = first.authorize_capture("core")

    with pytest.raises(BaselineAuthorizationError):
        second.capture("core", authorization=authorization)
    first.capture("core", authorization=authorization)
    with pytest.raises(BaselineAuthorizationError):
        first.capture("core", authorization=authorization)
    assert baselines.capture.call_count == 1


def test_fleet_approval_is_invalidated_when_the_device_set_changes():
    service, baselines = make_service(("core",))
    authorization = service.authorize_refresh_all("running")
    service.inventory.names.append("edge")

    with pytest.raises(BaselineAuthorizationError, match="does not match"):
        service.refresh_all("running", authorization=authorization)
    baselines.refresh_all.assert_not_called()


def test_capture_all_and_remove_forward_only_after_authorization():
    service, baselines = make_service()
    baselines.capture_all.return_value = {"status": "success"}
    capture = service.authorize_capture_all("startup")
    assert service.capture_all("startup", 2, authorization=capture) == {
        "status": "success"
    }
    baselines.capture_all.assert_called_once_with("startup", 2)

    baselines.remove.return_value = True
    remove = service.authorize_remove("edge")
    assert service.remove("EDGE", authorization=remove) is True
    baselines.remove.assert_called_once_with("EDGE")


def test_policy_rejects_non_baseline_and_inconsistent_write_intent():
    policy = BaselineWritePolicy()
    with pytest.raises(BaselineAuthorizationError):
        policy.authorize("refresh_mac_observations", ("core",), source=None, replace=False)
    with pytest.raises(BaselineAuthorizationError):
        policy.authorize(
            "refresh_configuration_baselines", ("core",),
            source="running", replace=False,
        )
