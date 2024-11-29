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
        tool_owner = "Outflank"
        tool_name = "Spray-AD"
        tool_url = "https://github.com/outflanknl/Spray-AD"
    strings:
        $ = "SprayAD"
    condition:
        any of them
}

rule dcsync_secretsdump {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1003.006"
        tool_name = "Impacket"
        tool_component = "secretsdump"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $dsruapi = " DRSUAPI "  // The API used by DCSync, included in the secretsdump output
        $justdcuser = " -just-dc-user "
    condition:
        any of them
}

rule GMSAPasswordReader {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1555"
        tool_name = "GMSAPasswordReader"
        tool_url = "https://github.com/rvazarkar/GMSAPasswordReader"
    strings:
        $ = "Calculating hashes for Old Value"
        $ = "Calculating hashes for Current Value"
    condition:
        all of them
}
