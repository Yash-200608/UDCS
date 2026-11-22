"""Local resource protection engine.

The governor decides, locally and every ~1 s, how much this machine may lend.
It never waits for the controller: losing the network never weakens protection.
"""
