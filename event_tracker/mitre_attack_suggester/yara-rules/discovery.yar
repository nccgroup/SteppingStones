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
    strings:
        $ = "portscan" nocase
    condition:
        any of them
}

rule netGroupListMembers {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1069.002"
    strings:
        $ = "netGroupListMembers"
    condition:
        any of them
}
