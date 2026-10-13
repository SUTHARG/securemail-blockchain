RULES FOR ALL WORK ON SECUREMAILSCOPE
1. docs/ARCHITECTURE.md is the specification. Do not invent behavior it does not define. If something is ambiguous or missing, STOP and list your questions instead of choosing. If I tell you to proceed, record each choice in docs/decisions/NNN-title.md.
2. The engine is deterministic: the same PCAP and the same engine release give byte-identical output. No wall-clock time, random values, floats, dict or set iteration order, locale, or timezone in any hashed or written output. Sort explicitly.
3. Hashed data uses integers and ASCII keys only. Timestamps are integer epoch seconds taken from the PCAP record header, never converted through floats.
4. Never store, log, or print credential values or email content. Evidence is stream and packet references only.
5. The engine is passive: it never makes a network call.
6. Only hashes and results go on-chain. No PCAP content or raw evidence.
7. Every module ships with tests. A task is not done until its tests pass and the acceptance check in the prompt is satisfied.
8. Pin exact dependency versions. Do not add a dependency the prompt does not allow without asking.
9. Do not change files outside the scope of the prompt. List every file you created or changed at the end.
SCOPE: PROJECT COMPLETE across all Milestones M1-M5 (Phases 0-9), Tier 2 (T2.1-T2.7), and Tier 3 (T3.1-T3.3). All 294 unit and integration tests pass, and all 9 kill-and-resume chaos scenarios pass.
