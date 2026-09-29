<!-- Two lines: what this changes and why. The reasoning for each change goes in its commit message. -->


**Bump after merge:** minor / patch / none <!-- RELEASING.md's table decides; none only when no user would notice -->

- [ ] `CHANGELOG.md` `[Unreleased]` has a line for what a user would notice, marked **Breaking** where it is
- [ ] Any wire change (SID, NRC, DID, RID, DFI, reason or byte layout) is in both `udsota_wire.h` and `client/udsota/wire.py`

**Where it ran:** <!-- CI runs the host tests, the client, the pipe and vcan e2e and the ESP-IDF builds. Name anything
beyond that: QEMU, or the board, transceiver and tester on a real bus. A change to the update path (first-block
check, erase, verify, activate, confirm, 0x27) that has not run on hardware says so here and in its CHANGELOG line. -->
