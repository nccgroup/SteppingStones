rule schtask {
    meta:
        mitre_att_tactic = "TA0003"
        mitre_att_technique = "T1053.005"
    strings:
        $ = "schtask"
    condition:
        any of them
}