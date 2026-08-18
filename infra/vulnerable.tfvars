# INTENTIONALLY VULNERABLE — local educational material.
#
# This value set is the whole demonstration. Read it: nothing here is malformed,
# nothing is hostile, and nothing is an exploit. It is a request, and the
# platform will grant it exactly.
#
# The refund export's readers become everyone, from everywhere. The admin
# surface switches to a profile whose addresses live in a module default, so the
# words on this page are "*", "0.0.0.0/0" and "shared-host" — and the ingress
# ranges that make the admin port reachable from every address are not on this
# page at all.

export_readers        = ["*"]
export_reader_sources = ["0.0.0.0/0"]

status_readers        = ["*"]
status_reader_sources = ["0.0.0.0/0"]

assets_readers        = ["finance-reporting"]
assets_reader_sources = ["10.20.0.0/16"]

admin_profile = "shared-host"
