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
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $ = "netGroupListMembers"
    condition:
        any of them
}
