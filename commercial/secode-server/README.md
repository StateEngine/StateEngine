# Private SE Code composition

This package supplies the embedded StateEngine host to SE Code's persistent
service. The public SE Code executable supplies no StateEngine host.

Native capture source IDs derive from the StateEngine session and vendor turn,
independently of the observation timestamp. Pre-alpha stores containing source
IDs from the previous timestamp-derived scheme are not migrated by this change.
The timestamp replay qualification uses fresh stores.

Capture delivery keys are carried only in the host's capture batch and reply,
outside the immutable source metadata. Existing history remains readable, but
pre-alpha source metadata containing `request_key` is not migrated: replaying
those turns with the new metadata can refuse as an immutable-source conflict.
Start a new session or use a fresh pre-alpha store to capture new turns.
