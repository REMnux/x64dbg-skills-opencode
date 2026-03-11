# Vulnerability Report

**Target**: {{target_name}}
**Date**: {{date}}
**Analyst**: {{analyst}}

---

## Executive Summary

{{brief_summary_of_findings}}

## Target Information

| Field | Value |
|---|---|
| Binary | {{binary_path}} |
| Architecture | {{arch}} |
| Module Base | {{module_base}} |
| Entry Point | {{entry_point}} |
| Mitigations | {{mitigations_aslr_dep_cfg_cookies}} |

## Reconnaissance

### Imports of Interest

| Import | Category | Call Sites | Risk |
|---|---|---|---|
| {{import_name}} | {{category}} | {{xref_count}} | {{risk_level}} |

### Exports of Interest

| Export | Address | Notes |
|---|---|---|
| {{export_name}} | {{address}} | {{notes}} |

## Triaged Attack Surface

| Rank | Address | Function | I/O Source | Sink Type | Risk | Status |
|------|---------|----------|------------|-----------|------|--------|
| {{rank}} | {{address}} | {{function}} | {{io_source}} | {{sink_type}} | {{risk}} | {{investigated/confirmed/not_vuln}} |

## Confirmed Vulnerabilities

### {{vuln_id}}: {{vuln_title}}

| Field | Value |
|---|---|
| Type | {{vuln_type}} |
| Location | {{address_and_function}} |
| I/O Source | {{input_source}} |
| Sink | {{dangerous_operation}} |
| Severity | {{severity}} |
| CVSS (est.) | {{cvss_estimate}} |

#### Description

{{detailed_description_of_the_vulnerability}}

#### Root Cause

{{root_cause_analysis — missing bounds check, integer wrap, logic flaw, etc.}}

#### Trigger Conditions

{{what_input_triggers_the_bug_and_under_what_conditions}}

#### Impact

{{what_an_attacker_can_achieve — crash, code execution, info leak, privilege escalation, etc.}}

#### Proof of Concept

**Script**: `./exploits/poc_{{vuln_name}}.py`

```
{{brief_description_of_poc_payload_and_delivery}}
```

**Evidence**:
- Register state at crash/exploitation: {{register_dump}}
- Stack/memory state: {{relevant_memory_hex}}
- Screenshots or debugger output: {{notes}}

#### Recommended Fix

{{suggested_remediation — add bounds check, use safe function, validate integer arithmetic, etc.}}

---

## Investigated but Not Vulnerable

| Address | Function | I/O Source | Reason Not Vulnerable |
|---|---|---|---|
| {{address}} | {{function}} | {{io_source}} | {{reason}} |

## Annotations Applied

| Address | Type | Text |
|---|---|---|
| {{address}} | Label / Comment | {{annotation_text}} |

## Notes

{{additional_observations_methodology_notes_or_caveats}}