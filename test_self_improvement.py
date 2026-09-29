#!/usr/bin/env python3
"""Test Self-Improvement Engine v2.0"""
import sys
sys.path.insert(0, "/mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND")

from vrin_SOC.dev.self_improvement import (
    SelfImprovementEngine, get_improvement_engine,
    log_interaction, get_report,
    package_skill, log_error, record_feedback,
)

passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")

print("Vrindha Self-Improvement Engine v2.0 — Functional Test")
print("=" * 60)

# Use the module-level singleton
engine = get_improvement_engine()
print(f"Engine: {len(engine.interactions)} interactions, {len(engine.skills)} skills")

# Test 2: Log a failure
rec2 = log_interaction("explain quantum encryption", "I don't know about that", mode="soc")
check("Log failure interaction", rec2.outcome == "failure")
print(f"        outcome={rec2.outcome}")

# Test 3: Knowledge gap detected
gaps = [g for g in engine.knowledge_gaps if not g.resolved]
check("Knowledge gap created", len(gaps) >= 1)
print(f"        ({len(gaps)} unresolved gap(s))")

# Test 4: Self-correction
def validate_fn(resp):
    is_bad = "i don't know" in resp.lower()
    return (not is_bad, "Response says I don't know" if is_bad else "")
corrected, was_fixed, steps = engine.self_correct(
    "I don't know about quantum encryption",
    validate_fn, max_attempts=2
)
check("Self-correction triggers", was_fixed is True)
check("Corrected message improved", "don't know" not in corrected.lower() or len(corrected) > 50)
print(f"        was_fixed={was_fixed}, steps={len(steps)}")

# Test 5: Package a skill
skill = package_skill(
    name="Nmap Scan Workflow",
    description="Run nmap scan, analyze results, report findings",
    trigger_pattern="scan network",
    steps=[
        {"description": "Validate target", "tool": "target_validator", "input": "target_ip"},
        {"description": "Run nmap -sV -sC", "tool": "nmap_tool", "input": "-sV -sC -T3"},
        {"description": "Analyze open ports", "tool": "threat_agent", "input": "port_results"},
        {"description": "Build summary report", "tool": "brain", "input": "build_summary"},
    ],
    tools_required=["nmap", "nmap_tool", "threat_agent"],
    success_criteria=["Target validated", "Scan completed", "Report generated"],
)
check("Skill packaged", skill.name == "Nmap Scan Workflow")
check("Skill has 4 steps", len(skill.steps) == 4)
check("Skill has trigger", skill.trigger_pattern == "scan network")
print(f"        skill={skill.name}, {len(skill.steps)} steps, trigger='{skill.trigger_pattern}'")

# Test 6: Find matching skill
found = engine.find_matching_skill("scan network 10.0.0.1")
check("Skill matching works", found is not None and found.name == "Nmap Scan Workflow")
print(f"        found={found.name if found else 'NONE'}")

# Test 7: Error logging + search
log_error("ImportError", "No module named 'nonexistent'", context="Loading module", resolution="Use fallback")
similar = engine.find_similar_errors("No module named something")
check("Error logged and searchable", len(similar) >= 1)
print(f"        ({len(similar)} similar error(s) found)")

# Test 8: Full report
report = get_report()
check("Report contains title", "Self-Improvement Report" in report)
check("Report mentions skills", "Skills Packaged" in report)
print(f"        ({len(report)} chars)")

# Test 8: Human feedback (use engine2 directly)
engine2 = SelfImprovementEngine()
engine2.log_interaction("who are you", "I am Vrindha", mode="soc")
engine2.record_human_feedback(0, "Good answer but add more detail about cybersecurity focus",
    correction="I am Vrindha, an AI cybersecurity companion who helps SOC analysts detect and respond to threats")
check("Human feedback recorded", len(engine2.human_feedback) >= 1)
print(f"        ({len(engine2.human_feedback)} feedback(s))")

print()
print("=" * 60)
if failed == 0:
    print(f"ALL {passed} TESTS PASSED — Self-Improvement Engine v2.0 is fully functional")
else:
    print(f"{passed} passed, {failed} failed")
print("=" * 60)
