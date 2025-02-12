rule kerberoast {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1558.003"
    strings:
        $ = "kerberoast" nocase
    condition:
        any of them
}

rule impacket_kerberoast {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1558.003"
        tool_name = "Impacket"
        tool_component = "GetUserSPNs"
        tool_url = "https://github.com/fortra/impacket"
        description = "Kerberoast using impacket"
    strings:
        $command = "GetUserSPNs"
        $request_param = "-request"
    condition:
        $command and $request_param
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

rule secretsdump_hivefiles_lsa {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1003.004"
        tool_name = "Impacket"
        tool_component = "secretsdump"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $command_1 = "secretsdump.py"
        $command_2 = "impacket-secretsdump"
        $param_1 = "local"
        $param_2 = "-security"
    condition:
        any of ($command_1, $command_2) and all of ($param_1, $param_2)
}

rule secretsdump_hivefiles_cdc { // Same as above rule, but with "Cached Domain Credentials" technique
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1003.005"
        tool_name = "Impacket"
        tool_component = "secretsdump"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $command_1 = "secretsdump.py"
        $command_2 = "impacket-secretsdump"
        $param_1 = "local"
        $param_2 = "-security"
    condition:
        any of ($command_1, $command_2) and all of ($param_1, $param_2)
}

rule impacket_ldapshell_laps {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1555"
        tool_name = "Impacket"
        tool_component = "ldap_shell"
        tool_url = "https://github.com/fortra/impacket"
        description = "Use LDAP to read LAPS password for {{ subcommand_1.1 }}"
    strings:
        $command_1 = "ldap_shell.py"
        $subcommand_1 = /get_laps_password .+\$/  // Ensure there's a $ in the target name to avoid the help text
    condition:
        $command_1 and $subcommand_1
}

rule certipy_ldapshell_laps {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1555"
        tool_name = "Certipy"
        tool_url = "https://github.com/ly4k/Certipy"
        description = "Authenticate to LDAP with certificate and read LAPS password for {{ subcommand_1.1 }}"
    strings:
        $command_1 = "certipy" // Will cover the alternative certipy-ad command well enough too
        $command_2 = " auth "
        $param_1 = "-ldap-shell"
        $subcommand_1 = /get_laps_password .+\$/  // Ensure there's a $ in the target name to avoid the help text
    condition:
        all of them
}

rule certipy_req {
    meta:
        mitre_att_tactic = "TA0006"
        mitre_att_technique = "T1649"
        tool_name = "Certipy"
        tool_url = "https://github.com/ly4k/Certipy"
        description = "Request certificate for {{ upn_param.1 }} on {{ upn_param.2 }} using template {{ template_param.1 }}"
    strings:
        $command_1 = "certipy" // Will cover the alternative certipy-ad command well enough too
        $command_2 = " req "
        $upn_param = /-upn \S+/
        $template_param = /-template \S+/
    condition:
        all of them
}
