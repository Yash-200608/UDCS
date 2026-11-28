"""NVIDIA GPU discovery and telemetry through NVML.

NVML ships with the NVIDIA driver (no CUDA toolkit needed). Every query is
best-effort: consumer GPUs commonly return NVML_ERROR_NOT_SUPPORTED for
utilization and power (verified on a GeForce GT 730), and those fields become
None rather than failing discovery. A machine without an NVIDIA driver yields
an empty GPU list plus a human-readable `error`.

NVML is started lazily, by its first user, never at agent start: nvmlInit() makes a
fixed allocation in the driver's nvml.dll (~21-23 MiB on driver 32.0.16.2124) that
nvmlShutdown() does not release and that lasts for the life of the process
(docs/research/2026-11-28-i2-service-memory.md).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from types import ModuleType
from typing import Any

from udcs_shared.hardware import GpuInfo
from udcs_shared.telemetry import GpuTelemetry

logger = logging.getLogger(__name__)
SHUTDOWN_LOCK_TIMEOUT_SECONDS = 2.0


def _import_pynvml() -> ModuleType:
    import pynvml

    return pynvml


def _text(value: object) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _nvml_errors(lib: Any) -> tuple[type[BaseException], ...]:
    """Every exception NVML bindings raise for 'this query failed'.

    `NVMLLibraryMismatchError` is *not* a subclass of `NVMLError`: it is raised when
    the binding is newer than the driver's nvml.dll (verified on driver 456.71,
    where `_v3` entry points are missing). Lab PCs with old GPUs are pinned to old
    drivers, so this must be treated as "field unsupported", not as a crash.
    """
    errors: list[type[BaseException]] = [lib.NVMLError]
    mismatch = getattr(lib, "NVMLLibraryMismatchError", None)
    if isinstance(mismatch, type) and issubclass(mismatch, BaseException):
        errors.append(mismatch)
    return tuple(errors)


class Nvml:
    def __init__(self, loader: Callable[[], ModuleType] = _import_pynvml) -> None:
        self._loader = loader
        self._lib: Any = None
        self._lock = threading.Lock()  # one nvmlInit at a time, however many callers
        self._attempted = False  # has any caller tried to start NVML yet?
        self.error: str | None = None

    @property
    def available(self) -> bool:
        return self._lib is not None

    def ensure_started(self) -> None:
        """(Re)initialize NVML if it is not running. Safe to call repeatedly and from any
        thread: concurrent callers wait, and only one of them calls nvmlInit."""
        if self._lib is not None:
            return
        with self._lock:
            if self._lib is not None:  # another thread started it while we waited
                return
            self._attempted = True
            try:
                lib = self._loader()
            except ImportError:
                self.error = "nvidia-ml-py is not installed"
                return
            try:
                lib.nvmlInit()
            except _nvml_errors(lib) as exc:
                self.error = f"NVML unavailable: {_text(exc)}"
                logger.info("no usable NVIDIA driver: %s", self.error)
                return
            self._lib = lib
            self.error = None

    def shutdown(self, timeout: float = SHUTDOWN_LOCK_TIMEOUT_SECONDS) -> None:
        # Bounded: if another thread is stuck inside nvmlInit (a hung driver), the agent's
        # stop must not hang behind it. The process is exiting; skipping is harmless.
        if not self._lock.acquire(timeout=timeout):
            logger.warning(
                "NVML start still in progress after %.0f s; skipping nvmlShutdown", timeout
            )
            return
        try:
            if self._lib is None:
                return
            try:
                self._lib.nvmlShutdown()
            except _nvml_errors(self._lib):
                logger.debug("nvmlShutdown failed", exc_info=True)
            self._lib = None
        finally:
            self._lock.release()

    def __enter__(self) -> Nvml:
        self.ensure_started()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.shutdown()

    def _call(self, name: str, *args: Any) -> Any:
        fn = getattr(self._lib, name, None)
        if fn is None:  # older binding without this function
            return None
        try:
            return fn(*args)
        except _nvml_errors(self._lib):
            return None

    def _handles(self) -> list[tuple[int, Any]]:
        if self._lib is None:
            return []
        count = self._call("nvmlDeviceGetCount")
        if count is None:
            # The driver went away under us (update/reset); re-init on next discovery.
            with self._lock:
                self.error = "NVML stopped responding"
                self._lib = None
            return []
        handles = []
        for index in range(min(int(count), 32)):
            handle = self._call("nvmlDeviceGetHandleByIndex", index)
            if handle is not None:
                handles.append((index, handle))
        return handles

    def gpu_inventory(self) -> list[GpuInfo]:
        handles = self._handles()
        if not handles:
            return []
        driver = self._call("nvmlSystemGetDriverVersion")
        cuda = self._call("nvmlSystemGetCudaDriverVersion")
        cuda_version = f"{cuda // 1000}.{(cuda % 1000) // 10}" if isinstance(cuda, int) else None
        gpus = []
        for index, handle in handles:
            memory = self._call("nvmlDeviceGetMemoryInfo", handle)
            capability = self._call("nvmlDeviceGetCudaComputeCapability", handle)
            pci = self._call("nvmlDeviceGetPciInfo", handle)
            uuid = self._call("nvmlDeviceGetUUID", handle)
            gpus.append(
                GpuInfo(
                    index=index,
                    vendor="nvidia",
                    name=_text(self._call("nvmlDeviceGetName", handle) or "unknown NVIDIA GPU")[
                        :256
                    ],
                    uuid=_text(uuid)[:128] if uuid else None,
                    pci_bus_id=_text(pci.busId)[:64] if pci is not None else None,
                    memory_total_bytes=int(memory.total) if memory is not None else None,
                    compute_capability=f"{capability[0]}.{capability[1]}" if capability else None,
                    driver_version=_text(driver)[:32] if driver else None,
                    cuda_driver_version=cuda_version,
                )
            )
        return gpus

    def gpu_telemetry(self) -> list[GpuTelemetry]:
        if not self._attempted:
            # First use may be telemetry. A failed or lost NVML is retried by inventory
            # (collect_inventory -> ensure_started), not on every telemetry sample.
            self.ensure_started()
        samples = []
        for index, handle in self._handles():
            utilization = self._call("nvmlDeviceGetUtilizationRates", handle)
            memory = self._call("nvmlDeviceGetMemoryInfo", handle)
            temperature = self._call(
                "nvmlDeviceGetTemperature", handle, getattr(self._lib, "NVML_TEMPERATURE_GPU", 0)
            )
            power_mw = self._call("nvmlDeviceGetPowerUsage", handle)
            samples.append(
                GpuTelemetry(
                    index=index,
                    utilization_percent=min(100.0, float(utilization.gpu))
                    if utilization is not None
                    else None,
                    memory_used_bytes=int(memory.used) if memory is not None else None,
                    memory_total_bytes=int(memory.total) if memory is not None else None,
                    temperature_c=float(temperature) if temperature is not None else None,
                    power_watts=power_mw / 1000.0 if power_mw is not None else None,
                )
            )
        return samples
