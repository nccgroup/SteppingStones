Yara rules for matching the raw input/out of command line or C2 tooling. Each rule should include the following metadata:

* `mitre_att_tactic` *required* MITRE ATT&CK Tactic ID, e.g. "TA0006"
* `mitre_att_technique` *required*  MITRE ATT&CK (Sub)technique ID, e.g. "T1046" or "T1003.006"
* `tool_owner` *optional* the company (if any) resposible for the tool, e.g. "Fortra"
* `tool_name` *optional* the common name for the tool, e.g. "Cobalt Strike"
* `tool_url` *optional* URL to obtain the tool, e.g. "https://www.cobaltstrike.com/"
* `tool_component` *optional* The specific component of the tool if applicable, e.g. "secretsdump"
