"""Optional read-only Windows activity monitor tests."""

from __future__ import annotations

from ssg8.core.models import EventCategory
from ssg8.services.event_log import EventLog
from ssg8.services.paranoia.monitor import ObservedProcess, WindowsActivityMonitor


def test_monitoring_is_disabled_by_default() -> None:
    monitor = WindowsActivityMonitor()
    assert monitor.enabled() is False
    assert monitor.baseline_size() == 0


def test_only_process_id_and_name_are_collected() -> None:
    assert set(ObservedProcess.__dataclass_fields__) == {"pid", "name"}


def test_start_and_stop_require_opt_in() -> None:
    events = EventLog()
    monitor = WindowsActivityMonitor(events)

    started = monitor.start()
    if monitor.available():
        # On Windows the documented read-only snapshot should be usable.
        assert started is True
        assert monitor.enabled() is True
        assert monitor.stop() is True
        assert monitor.enabled() is False
    else:
        assert started is False
        assert monitor.enabled() is False

    assert any(
        entry.category is EventCategory.MONITORING for entry in events.entries()
    )


def test_unavailable_monitoring_falls_back_safely(monkeypatch) -> None:
    events = EventLog()
    monitor = WindowsActivityMonitor(events)
    monkeypatch.setattr(monitor, "available", lambda: False)

    assert monitor.start() is False
    assert monitor.enabled() is False
    assert monitor.snapshot() == ()
    assert "unavailable" in monitor.availability_note().casefold()
    assert any(
        "demonstration-only mode" in entry.message.casefold()
        for entry in events.entries()
    )


def test_snapshot_returns_only_approved_metadata() -> None:
    monitor = WindowsActivityMonitor()
    for process in monitor.snapshot():
        assert isinstance(process.pid, int)
        assert isinstance(process.name, str)
        assert process.pid > 0
        assert process.name


def test_observation_diff_records_started_and_exited_processes(monkeypatch) -> None:
    events = EventLog()
    monitor = WindowsActivityMonitor(events)
    baseline = (
        ObservedProcess(10, "explorer.exe"),
        ObservedProcess(20, "notepad.exe"),
    )
    after = (
        ObservedProcess(10, "explorer.exe"),
        ObservedProcess(30, "calculator.exe"),
    )
    monkeypatch.setattr(monitor, "snapshot", lambda: baseline)
    monkeypatch.setattr(monitor, "available", lambda: True)

    assert monitor.start() is True
    monkeypatch.setattr(monitor, "snapshot", lambda: after)
    current = monitor.observe()

    assert current == after
    assert any(
        "process change observed" in entry.message.casefold()
        and "calculator.exe" in entry.message
        and "notepad.exe" in entry.message
        for entry in events.entries()
    )


def test_monitor_has_no_process_control_api() -> None:
    monitor = WindowsActivityMonitor()
    forbidden = {
        "terminate",
        "kill",
        "terminate_process",
        "suspend",
        "set_priority",
        "intercept_network",
    }
    assert not (forbidden & set(dir(monitor)))


def test_observe_while_disabled_does_not_log_process_changes() -> None:
    events = EventLog()
    monitor = WindowsActivityMonitor(events)
    before = events.count()

    monitor.observe()

    assert events.count() == before
