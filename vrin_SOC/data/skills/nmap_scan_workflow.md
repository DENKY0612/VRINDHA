# Nmap Scan Workflow

**Description:** Run nmap scan, analyze results, report findings
**Trigger:** `scan network`
**Tools required:** nmap, nmap_tool, threat_agent
**Created:** 2026-09-29T19:49:44.608957
**Used:** 0 time(s)

## Steps

1. **Validate target**
   - Tool: `target_validator`
   - Input: `target_ip`

2. **Run nmap -sV -sC**
   - Tool: `nmap_tool`
   - Input: `-sV -sC -T3`

3. **Analyze open ports**
   - Tool: `threat_agent`
   - Input: `port_results`

4. **Build summary report**
   - Tool: `brain`
   - Input: `build_summary`

## Success Criteria

- [ ] Target validated
- [ ] Scan completed
- [ ] Report generated
