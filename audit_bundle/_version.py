"""The verifier's version and release status — ONE source, read by everything.

Both pyprojects (the internal one and the public `veriker` one the export
installs) declare `dynamic = ["version"]` and read `__version__` from here;
`veriker/cli/verify.py` stamps it, with `RELEASE_STATUS`, onto every verdict face and
onto the first line of the terminal output; the public README's literal
console blocks carry the same line, ratcheted by `tests/test_release_label.py`
so a bump here cannot ship with a README that shows the old one.

WHY THE STATUS TRAVELS WITH THE ARTIFACT. A verifier's failure mode is a
silent false PASS, and the honest framing of a young one is "experimental:
no production / verified / 1.0 claim until a dated third-party audit has
completed and its findings are fixed". A README can say that; a verdict that
someone forwards cannot, unless the label is on it. So the label is on it.

Stdlib-only, import-free: `setuptools` reads `__version__` by AST literal
evaluation, and the offline CLI's stdlib import boundary must not widen.
"""

#: PEP 440. 0.x means experimental (see RELEASE_STATUS). The only path off
#: 0.x is the one the public README states: completed third-party audit +
#: findings fixed + the signing ceremony. Never "1.0.0rc1" or any 1.x string
#: while RELEASE_STATUS is "experimental".
__version__ = "0.2.1"

#: One of: "experimental". No other value exists yet — adding one is a
#: release-posture decision, not an edit.
RELEASE_STATUS = "experimental"
