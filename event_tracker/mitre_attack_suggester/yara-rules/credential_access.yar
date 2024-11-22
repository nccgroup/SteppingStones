rule kerberoast {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1558.003"
    strings:
        $ = "kerberoast" nocase
    condition:
        any of them
}

rule sprayad {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1110.003"
    strings:
        $ = "SprayAD"
    condition:
        any of them
}

rule dcsync_secretsdump {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1003.006"
    strings:
        $dsruapi = " DRSUAPI "  // The API used by DCSync, included in the secretsdump output
        $justdcuser = " -just-dc-user "
    condition:
        any of them
}
