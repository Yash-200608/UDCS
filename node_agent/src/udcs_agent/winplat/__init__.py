"""Thin, typed ctypes wrappers over the Win32 APIs the agent depends on.

Everything here is Windows-only. Callers import submodules lazily and check
`IS_WINDOWS` so the rest of the agent (and its tests) still import elsewhere.
Each wrapper raises `WinApiError` with the Win32 error code instead of failing
silently, because silent failure of a protection mechanism is the worst case.
"""

import sys

IS_WINDOWS = sys.platform == "win32"
