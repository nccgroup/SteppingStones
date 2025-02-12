rule net_view {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1135"
    strings:
        $ = "net view"
    condition:
        any of them
}

rule portscan {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1046"
        tool_owner = "Fortra"
        tool_name = "Cobalt Strike"
        tool_url = "https://www.cobaltstrike.com/"
    strings:
        $ = "portscan" nocase
    condition:
        any of them
}

rule netGroupListMembers {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1069.002"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "netGroupListMembers"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $ = "netGroupListMembers"
    condition:
        any of them
}

rule ldapsearch {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1087.002"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "ldapsearch"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $ = "ldapsearch"
    condition:
        any of them
}

rule wmiquery {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1082"
        tool_name = "Impacket"
        tool_component = "wmiquery"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $ = "wmiquery.py"
        $ = "impacket-wmiquery"
    condition:
        any of them
}

rule cim_local_service_query {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1007"
        tool_name = "Powershell"
    strings:
        $ = "Get-CimInstance" nocase
        $ = " FROM Win32_Service" nocase
    condition:
        all of them
}