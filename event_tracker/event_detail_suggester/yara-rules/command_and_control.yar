rule link_smb {
    meta:
        mitre_att_tactic = "TA0011"
        mitre_att_technique = "T1071.002"
        tool_owner = "Fortra"
        tool_name = "Cobalt Strike"
        tool_url = "https://www.cobaltstrike.com/"
    strings:
        $ = /^link /
    condition:
        any of them
}