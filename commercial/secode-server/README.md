# Private SE Code composition

This package supplies the embedded StateEngine host to SE Code's persistent
service. The public SE Code executable supplies no StateEngine host.

Native capture source IDs derive from the StateEngine session and vendor turn,
independently of the observation timestamp. Pre-alpha stores containing source
IDs from the previous timestamp-derived scheme are not migrated by this change.
The timestamp replay qualification uses fresh stores.
