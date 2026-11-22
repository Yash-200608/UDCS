"""Wire contracts shared by the UDCS controller and node agent.

Everything in this package crosses a trust boundary: the controller must treat
agent-supplied instances as untrusted input, which is why every model forbids
unknown fields and bounds every value.
"""

__version__ = "0.1.0"
