"""Behavior contract for the profile-scoped login-backend registry."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

import pytest

from agent.vault_backends.base import LoginBackend
from agent.vault_backends.registry import (
    LoginBackendProvider,
    _reset_for_tests,
    list_providers,
    register_provider,
    restore_registration,
    snapshot_registration,
)
from hermes_constants import hermes_home_key


class BrokerBackend(LoginBackend):
    name = "broker"
    display_name = "Broker"
    prefix = "broker:"
    needs_unlock = True

    def __init__(self, config: Mapping[str, Any]):
        self.config = config

    def list_items(self):
        return []

    def get_meta(self, handle):
        return None

    def resolve_password(self, handle):
        return ""


@pytest.fixture(autouse=True)
def reset_registry():
    _reset_for_tests()
    yield
    _reset_for_tests()


@pytest.fixture
def profile_a(tmp_path):
    return hermes_home_key(tmp_path / "profile-a")


@pytest.fixture
def profile_b(tmp_path):
    return hermes_home_key(tmp_path / "profile-b")


@pytest.fixture
def profile_scope(profile_a):
    return profile_a


def test_registry_rejects_duplicate_name_and_prefix(profile_scope):
    first = LoginBackendProvider(
        name="broker",
        display_name="Broker",
        prefix="broker:",
        needs_unlock=True,
        factory=BrokerBackend,
    )
    register_provider(first, scope=profile_scope)

    with pytest.raises(ValueError, match="backend name 'broker' is already registered"):
        register_provider(replace(first, prefix="other:"), scope=profile_scope)
    with pytest.raises(ValueError, match="handle prefix 'broker:' is already registered"):
        register_provider(replace(first, name="other"), scope=profile_scope)


def test_registry_is_profile_scoped_and_restores_on_identity(profile_a, profile_b):
    provider = LoginBackendProvider(
        name="broker",
        display_name="Broker",
        prefix="broker:",
        needs_unlock=True,
        factory=BrokerBackend,
    )
    register_provider(provider, scope=profile_a)

    assert list_providers(scope=profile_a) == [provider]
    assert list_providers(scope=profile_b) == []
    assert restore_registration("broker", provider, None, scope=profile_a) is True
    assert list_providers(scope=profile_a) == []


def test_provider_validates_factory_result(profile_scope):
    provider = LoginBackendProvider(
        name="broker",
        display_name="Broker",
        prefix="broker:",
        needs_unlock=True,
        factory=BrokerBackend,
    )
    config = {"endpoint": "https://broker.example"}

    backend = provider.create(config)

    assert isinstance(backend, BrokerBackend)
    assert backend.config is config


def test_restore_requires_the_current_provider_identity(profile_scope):
    provider = LoginBackendProvider(
        name="broker",
        display_name="Broker",
        prefix="broker:",
        needs_unlock=True,
        factory=BrokerBackend,
    )
    register_provider(provider, scope=profile_scope)

    impostor = replace(provider)

    assert snapshot_registration("broker", scope=profile_scope) is provider
    assert restore_registration("broker", impostor, None, scope=profile_scope) is False
    assert list_providers(scope=profile_scope) == [provider]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"name": ""}, "backend name must be a non-empty lowercase string"),
        ({"name": "Broker"}, "backend name must be a non-empty lowercase string"),
        ({"prefix": ""}, "handle prefix must be a non-empty string"),
        ({"factory": None}, "login backend factory must be callable"),
    ],
)
def test_registry_validates_provider_metadata(profile_scope, changes, message):
    values = {
        "name": "broker",
        "display_name": "Broker",
        "prefix": "broker:",
        "needs_unlock": True,
        "factory": BrokerBackend,
    }
    values.update(changes)
    provider = LoginBackendProvider(**values)

    with pytest.raises((TypeError, ValueError), match=message):
        register_provider(provider, scope=profile_scope)
