"""Minimal CUDA driver-API access (nvcuda.dll ships with the NVIDIA driver).

Used for the synthetic GPU workload, the GPU foreground benchmark and experiment
E1. A tiny PTX kernel is JIT-compiled by the driver, so no CUDA toolkit or
PyTorch is required -- important because PyTorch no longer supports old lab GPUs
such as the GT 730 (compute capability 3.5). Running this kernel proves only that
the *driver* can execute CUDA work; it says nothing about framework support.
"""

from __future__ import annotations

import ctypes
import time

# Each thread spins `iters` dependent FMAs, then writes one float. Kernel length is
# tuned (calibrate) to stay far below the 2 s WDDM TDR watchdog.
_PTX = (
    rb"""
.version 6.0
.target sm_30
.address_size 64

.visible .entry spin(
    .param .u64 out,
    .param .u32 iters
)
{
    .reg .pred %p<2>;
    .reg .b32 %r<4>;
    .reg .f32 %f<2>;
    .reg .b64 %rd<3>;

    ld.param.u64 %rd1, [out];
    ld.param.u32 %r1, [iters];
    mov.f32 %f1, 0f3F800000;
    mov.u32 %r2, 0;
LOOP:
    fma.rn.f32 %f1, %f1, 0f3F7FFFFF, 0f3A83126F;
    add.u32 %r2, %r2, 1;
    setp.lt.u32 %p1, %r2, %r1;
    @%p1 bra LOOP;
    cvta.to.global.u64 %rd2, %rd1;
    st.global.f32 [%rd2], %f1;
    ret;
}
"""
    + b"\0"
)


class CudaError(RuntimeError):
    def __init__(self, call: str, code: int) -> None:
        super().__init__(f"{call} failed with CUresult {code}")
        self.call = call
        self.code = code


class CudaDevice:
    def __init__(self, ordinal: int = 0, *, blocks: int = 64, threads: int = 256) -> None:
        self._cuda = ctypes.WinDLL("nvcuda")
        self.blocks, self.threads = blocks, threads
        self._ctx = ctypes.c_void_p()
        self._module = ctypes.c_void_p()
        self._fn = ctypes.c_void_p()
        self._out = ctypes.c_uint64()
        self._check("cuInit", 0)
        device = ctypes.c_int()
        self._check("cuDeviceGet", ctypes.byref(device), ordinal)
        name = ctypes.create_string_buffer(256)
        self._check("cuDeviceGetName", name, 256, device)
        self.name = name.value.decode(errors="replace")
        major, minor = ctypes.c_int(), ctypes.c_int()
        self._check("cuDeviceGetAttribute", ctypes.byref(major), 75, device)  # CC major
        self._check("cuDeviceGetAttribute", ctypes.byref(minor), 76, device)  # CC minor
        self.compute_capability = f"{major.value}.{minor.value}"
        self._check("cuCtxCreate_v2", ctypes.byref(self._ctx), 0, device)
        self._check("cuModuleLoadData", ctypes.byref(self._module), _PTX)
        self._check("cuModuleGetFunction", ctypes.byref(self._fn), self._module, b"spin")
        self._check("cuMemAlloc_v2", ctypes.byref(self._out), ctypes.c_size_t(4))

    def _check(self, call: str, *args: object) -> None:
        code = getattr(self._cuda, call)(*args)
        if code != 0:
            raise CudaError(call, code)

    def run_kernel(self, iters: int) -> float:
        """Launch once and wait; returns wall seconds."""
        out = ctypes.c_uint64(self._out.value)
        count = ctypes.c_uint32(iters)
        params = (ctypes.c_void_p * 2)(
            ctypes.cast(ctypes.byref(out), ctypes.c_void_p),
            ctypes.cast(ctypes.byref(count), ctypes.c_void_p),
        )
        started = time.perf_counter()
        self._check(
            "cuLaunchKernel", self._fn, self.blocks, 1, 1, self.threads, 1, 1, 0, None, params, None
        )
        self._check("cuCtxSynchronize")
        return time.perf_counter() - started

    def calibrate(self, target_seconds: float) -> int:
        iters = 1_000
        self.run_kernel(iters)  # JIT + warm-up
        for _ in range(12):
            elapsed = self.run_kernel(iters)
            if elapsed >= target_seconds * 0.8:
                break
            iters = int(iters * min(8.0, max(1.5, target_seconds / max(elapsed, 1e-4))))
        return max(1, int(iters * target_seconds / max(self.run_kernel(iters), 1e-4)))

    def close(self) -> None:
        if self._out.value:
            self._cuda.cuMemFree_v2(self._out)
            self._out = ctypes.c_uint64()
        if self._module:
            self._cuda.cuModuleUnload(self._module)
            self._module = ctypes.c_void_p()
        if self._ctx:
            self._cuda.cuCtxDestroy_v2(self._ctx)
            self._ctx = ctypes.c_void_p()
