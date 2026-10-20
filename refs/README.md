# Optional source references

There are **no Git submodules**. A normal SwiftPM clone or consumer build must not
download any reference repository. Only the small `pins.json` source map is
tracked. Research folders under `refs/` are ignored and are never package inputs.

To inspect a pin, make a manual checkout in an ignored folder. Fetch only that
commit; do not clone the complete Teleport history. Read the path/license rules
in `docs/PROVENANCE.md` before copying any material. The reference package is a
review input, not code to import.

`scripts/check-refs.py` reports absent optional checkouts without downloading
anything. If a checkout exists, it must match the pin and have no edits. Remove
manual checkouts after research to save disk space.
