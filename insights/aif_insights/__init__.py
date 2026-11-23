"""aif-insights: the factory's self-improvement loop, starting with collection.

Collect agent transcripts from a machine, redact them before they leave it,
summarise each session, and archive both to object storage. This package must
not import `software_factory`: it is reusable on its own, and talks to the
factory only through files (findings in the collector shape, in later phases).
"""

__version__ = "0.1.0.dev0"
