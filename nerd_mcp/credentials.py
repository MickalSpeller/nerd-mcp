"""Resolve SSH credentials without depending on desktop environment inheritance."""

import getpass
import os
import re
import sys
import warnings

from .domain.errors import InventoryError


def normalize_profile(profile):
    profile = profile.lower()
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", profile):
        raise InventoryError("Invalid credential profile: use letters, digits and underscores, starting with a letter.")
    return profile


def windows_backend():
    if sys.platform != "win32":
        raise InventoryError("Saved credentials require Windows. Use NERD credential environment variables on this platform.")
    try:
        import win32cred
        return win32cred
    except ImportError:
        raise InventoryError("Windows credential support is missing; reinstall the project dependencies.") from None


def read_saved(profile):
    profile = normalize_profile(profile)
    if sys.platform != "win32":
        return None
    backend = windows_backend()
    record = None
    for target in (f"nerd-mcp:{profile}", f"cisco-mcp:{profile}"):
        try:
            record = backend.CredRead(target, backend.CRED_TYPE_GENERIC)
            break
        except Exception as exc:
            if getattr(exc, "winerror", None) == 1168:
                continue
            raise InventoryError("Cannot read Windows Credential Manager. Run under the Windows account that saved the credentials.") from None
    if record is None:
        return None
    try:
        password = record["CredentialBlob"]
        if isinstance(password, bytes):
            password = password.decode("utf-16-le")
        username = record["UserName"]
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            raise ValueError
        return username, password
    except (KeyError, ValueError, TypeError):
        raise InventoryError(f"Stored credentials are invalid. Run: python -m nerd_mcp credentials set {profile}") from None


def resolve_credentials(profile):
    profile = normalize_profile(profile)
    prefix = f"NERD_{profile.upper()}"
    username, password = os.getenv(prefix + "_USERNAME"), os.getenv(prefix + "_PASSWORD")
    if username and password:
        return username, password, "environment"
    legacy_prefix = f"CISCO_{profile.upper()}"
    legacy_user = os.getenv(legacy_prefix + "_USERNAME")
    legacy_password = os.getenv(legacy_prefix + "_PASSWORD")
    if not username and not password and legacy_user and legacy_password:
        return legacy_user, legacy_password, "environment (legacy names)"
    saved = read_saved(profile)
    if saved:
        return *saved, "Windows Credential Manager"
    raise InventoryError(
        f"No complete credentials for profile '{profile}'. "
        f"Run: python -m nerd_mcp credentials set {profile} (Windows), "
        f"or set both {prefix}_USERNAME and {prefix}_PASSWORD."
    )


def save_interactive(profile):
    profile = normalize_profile(profile)
    backend = windows_backend()
    if not sys.stdin.isatty():
        raise InventoryError("Run credentials set in an interactive PowerShell window; do not pipe passwords.")
    print(f"Save or replace profile '{profile}' in Windows Credential Manager for this Windows account.")
    try:
        username = input("Device username: ").strip()
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Device password (hidden): ")
            confirmation = getpass.getpass("Confirm password (hidden): ")
    except (EOFError, getpass.GetPassWarning):
        raise InventoryError("Hidden credential entry unavailable. Use an interactive Windows PowerShell terminal.") from None
    if not username or not password:
        raise InventoryError("Username and password must not be empty. Nothing saved.")
    if password != confirmation:
        raise InventoryError("Passwords do not match. Nothing saved.")
    save_saved(profile, username, password)
    print(f"Saved profile '{profile}'. Password was not written to project files or Codex configuration.")


def save_saved(profile, username, password):
    """Persist already-collected credentials without reading terminal input."""
    profile = normalize_profile(profile)
    backend = windows_backend()
    if not isinstance(username, str) or not isinstance(password, str):
        raise InventoryError("Username and password must be text. Nothing saved.")
    username = username.strip()
    if not username or not password:
        raise InventoryError("Username and password must not be empty. Nothing saved.")
    if len(password.encode("utf-16-le")) > 2560:
        raise InventoryError("Password exceeds the Windows credential size limit. Nothing saved.")
    try:
        backend.CredWrite({
            "Type": backend.CRED_TYPE_GENERIC,
            "TargetName": f"nerd-mcp:{profile}",
            "UserName": username,
            "CredentialBlob": password,
            "Persist": backend.CRED_PERSIST_LOCAL_MACHINE,
            "Comment": "NERD MCP SSH credential profile",
        }, 0)
    except Exception:
        raise InventoryError("Could not save credentials to Windows Credential Manager.") from None


def remove_saved(profile):
    profile = normalize_profile(profile)
    backend = windows_backend()
    removed = False
    for target in (f"nerd-mcp:{profile}", f"cisco-mcp:{profile}"):
        try:
            backend.CredDelete(target, backend.CRED_TYPE_GENERIC)
            removed = True
        except Exception as exc:
            if getattr(exc, "winerror", None) == 1168:
                continue
            raise InventoryError("Could not remove credentials from Windows Credential Manager.") from None
    if not removed:
        raise InventoryError("No saved credentials for this profile.")
