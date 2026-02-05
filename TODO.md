Immediate TODOs

Decisions (please pick or provide prefs)
1) Execution environment
   - [x] Local host only (this machine is the sandbox) 
2) Message bus
   - [ ] JSONL files (MVP, simplest) 
   - [ ] Redis streams 
   - [ ] NATS 
3) Artifact store
   - [ ] Local ./artifacts (MVP) 
   - [ ] MinIO 
4) Policy engine
   - [ ] YAML allowlists (MVP) 
   - [ ] OPA/Rego 
5) MCP servers to start with
   - [ ] security-platform MCP (primary) 
   - [ ] fs (scoped) 
   - [ ] http(s) fetch (allowlist) 
   - [ ] git (read-only) 
6) Reporting format
   - [ ] Markdown + HTML export 
   - [ ] PDF 
   - [ ] Issue tickets (later)

Milestones
- M0: Repo skeleton + local runner + JSONL logs
- M1: Planner + Operator via MCP (security-platform + fs/http)
- M2: Policy gates; schedule basic recurring checks
- M3: Add git read-only + reporting export (HTML/PDF)

Safety Gates
- [ ] No network egress without allowlist (via MCP policies)
- [ ] No destructive ops without explicit approval
- [ ] Secrets isolated; ephemeral tokens; per-run identities

Notes
- Running locally; no extra container/VM layer by design.
