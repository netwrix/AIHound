"""Tests for the platform module."""

from aihound.core.platform import detect_platform, Platform


def test_detect_platform():
    plat = detect_platform()
    assert isinstance(plat, Platform)
    assert plat.value in ("windows", "macos", "linux", "wsl")


def test_platform_enum_values():
    assert Platform.WINDOWS.value == "windows"
    assert Platform.MACOS.value == "macos"
    assert Platform.LINUX.value == "linux"
    assert Platform.WSL.value == "wsl"
