rule impacket_ldapshell_enable_account {
    meta:
        mitre_att_tactic = "TA0004"
        mitre_att_technique = "T1078.002"
        tool_name = "Impacket"
        tool_component = "ldap_shell"
        tool_url = "https://github.com/fortra/impacket"
        description = "Enable the {{subcommand_1.1}} account via LDAP"
    strings:
        $command_1 = "ldap_shell.py"
        $subcommand_1 = /enable_account \S+/
        $subcommand_output_1 = "Original userAccountControl: "
        $subcommand_output_2 = "Updated userAccountControl attribute successfully"
    condition:
        all of them
}

rule certipy_ldapshell_enable_account {
    meta:
        mitre_att_tactic = "TA0004"
        mitre_att_technique = "T1078.002"
        tool_name = "Certipy"
        tool_url = "https://github.com/ly4k/Certipy"
        description = "Authenticate to LDAP with certificate and set new password for {{subcommand_1.1}}"
    strings:
        $command_1 = "certipy" // Will cover the alternative certipy-ad command well enough too
        $command_2 = " auth "
        $command_param_1 = "-ldap-shell"
        $subcommand_1 = /change_password \S+/
        $subcommand_output_1 = "Attempting to set new password of: "
    condition:
        all of them
}

rule impacket_ldapshell_change_password {
    meta:
        mitre_att_tactic = "TA0004"
        mitre_att_technique = "T1078.002"
        tool_name = "Impacket"
        tool_component = "ldap_shell"
        tool_url = "https://github.com/fortra/impacket"
        description = "Set new password for {{subcommand_1.1}} via LDAP"
    strings:
        $command_1 = "ldap_shell.py"
        $subcommand_1 = /change_password \S+/
        $subcommand_output_1 = "Attempting to set new password of: "
    condition:
        all of them
}

rule certipy_ldapshell_change_password {
    meta:
        mitre_att_tactic = "TA0004"
        mitre_att_technique = "T1078.002"
        tool_name = "Certipy"
        tool_url = "https://github.com/ly4k/Certipy"
        description = "Authenticate to LDAP with certificate and set new password for {{subcommand_1.1}}"
    strings:
        $command_1 = "certipy" // Will cover the alternative certipy-ad command well enough too
        $command_2 = " auth "
        $command_param_1 = "-ldap-shell"
        $subcommand_1 = /change_password \S+/
        $subcommand_output_1 = "Attempting to set new password of: "
    condition:
        all of them
}