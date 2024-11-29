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
