"""Additional Telegraph intents served by VulnRank (see telegraph/vulnrank-fixed.yaml).

Every endpoint here follows the same rules as the vulnerability endpoints: a single graded value at the
top level, always a 200 answer, `null` plus an explicit `status` instead of a guess when a source fails,
and answers corroborated by two independent upstreams wherever two exist.
"""
