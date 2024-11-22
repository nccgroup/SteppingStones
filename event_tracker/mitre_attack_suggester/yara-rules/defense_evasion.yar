rule msbuild {
    meta:
        mitre_att_tactic = "TA0005"
        mitre_att_technique = "T1127.001"
    strings:
        $ = "msbuild"
    condition:
        any of them
}