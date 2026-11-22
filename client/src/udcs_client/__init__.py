"""UDCS researcher client (`udcs`): package, validate, upload, submit, monitor, fetch.

Running user code stays disabled on the controller and on every node until the
ADR 0001 gates and administrator node-eligibility controls are complete. This
client never works around that: while it is off, `udcs submit` uploads and registers
the package (which validates it on the server) and creates no job.
"""

__version__ = "0.1.0"
