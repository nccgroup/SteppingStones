rule kerberoast {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1558.003"
    strings:
        $kerberoast = "kerberoast" nocase
    condition:
        $kerberoast
}

rule sprayad {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1110.003"
    strings:
        $sprayad = "SprayAD"
    condition:
        $sprayad
}
