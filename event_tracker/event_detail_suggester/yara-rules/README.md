## Metadata

Yara rules for matching the raw input/out of command line or C2 tooling. Each rule should include the following metadata:

* `mitre_att_tactic` *required* MITRE ATT&CK Tactic ID, e.g. "TA0006"
* `mitre_att_technique` *required*  MITRE ATT&CK (Sub)technique ID, e.g. "T1046" or "T1003.006"
* `tool_owner` *optional* the company (if any) resposible for the tool, e.g. "Fortra"
* `tool_name` *optional* the common name for the tool, e.g. "Cobalt Strike"
* `tool_url` *optional* URL to obtain the tool, e.g. "https://www.cobaltstrike.com/"
* `tool_component` *optional* The specific component of the tool if applicable, e.g. "secretsdump"
* `description` *optional* A moustache template which describes the action, e.g. "Request certificate for {{ upn_param.1 }} on {{ upn_param.2 }} using template {{ template_param.1 }}"

### Moustache Templates

Using the moustache template language the value which first matched a named pattern can be referenced.
The values have been split on a selection of common CLI delimiter symbols to allow referencing parts of the matched pattern.
For example the template `"Scanning {{ example.2 }}"` will render the 3rd array member after splitting the match for the `$example` pattern
in the Yara rule.

If the Yara rule contained:
```
    strings:
        $example = /--my-param \S+/
```
And the rule matched against `--my-param a:b:c` then the Moustache template would render as `"Scanning b"` as `b` is the 3rd entry in the split array: `["--my-param", "a", "b", "c"]`.
