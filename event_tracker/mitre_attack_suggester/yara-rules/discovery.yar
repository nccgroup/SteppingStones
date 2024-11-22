rule net_view {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1135"
    strings:
        $net_view = "net view"
    condition:
        $net_view
}

rule portscan {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1046"
    strings:
        $portscan = "portscan" nocase
    condition:
        $portscan
}
