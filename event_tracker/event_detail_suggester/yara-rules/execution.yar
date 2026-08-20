rule wmiexec {
    meta:
        mitre_att_tactic = "TA0002"
        mitre_att_technique = "T1047"
        tool_name = "Impacket"
        tool_component = "wmiexec"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $ = "wmiexec.py"
        $ = "impacket-wmiexec"
    condition:
        any of them
}

rule schtasksrun {
    meta:
        mitre_att_tactic = "TA0002"
        mitre_att_technique = "T1053.005"
        tool_owner = "TrustedSec"
        tool_name = "Remote Operations BOF"
        tool_component = "schtasksrun"
        tool_url = "https://github.com/trustedsec/CS-Remote-OPs-BOF"
    strings:
        $ = "schtasksrun"
    condition:
        any of them
}

rule oc2_exec_process {
    meta:
        mitre_att_tactic = "TA0002"
        mitre_att_technique = "T1106"
        tool_owner = "Outflank"
        tool_name = "C2"
        tool_component = "exec_process"
    strings:
        $ = "exec_process "
    condition:
        any of them
}