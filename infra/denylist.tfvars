# INTENTIONALLY VULNERABLE — local educational material.
#
# The same desired state as the misconfigured value set, written two other
# ordinary ways.
#
# The refund export's own permission is untouched: finance only, from the
# corporate segment. A *separate* permission resource carries the exposure, and
# it names its addresses as two halves of the address space rather than as one
# range. The admin surface uses the profile whose ranges are written the same
# way.
#
# Nothing here is evasion. Both are how people write these things. That is the
# point: a rule that matches a value matches only the value it was shown.

export_readers        = ["finance-reporting"]
export_reader_sources = ["10.20.0.0/16"]

status_readers        = ["*"]
status_reader_sources = ["0.0.0.0/0"]

assets_readers        = ["finance-reporting"]
assets_reader_sources = ["10.20.0.0/16"]

admin_profile      = "shared-host"
extra_export_grant = "anonymous"
