rule schtask {
    meta:
        mitre_att_tactic = "TA0003"
        mitre_att_technique = "T1053.005"
    strings:
        $ = "schtask"
    condition:
        any of them
}

rule impacket_ldapshell_add_user_to_group {
    meta:
        mitre_att_tactic = "TA0003"
        mitre_att_technique = "T1098.007"
        tool_name = "Impacket"
        tool_component = "ldap_shell"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $command_1 = "ldap_shell.py"
        $subcommand_1 = "add_user_to_group "
        $subcommand_output_1 = "Adding user: "
        $subcommand_output_2 = " to group "
    condition:
        all of them
}

rule certipy_ldapshell_add_user_to_group {
    meta:
        mitre_att_tactic = "TA0003"
        mitre_att_technique = "T1098.007"
        tool_name = "Certipy"
        tool_url = "https://github.com/ly4k/Certipy"
    strings:
        $command_1 = "certipy" // Will cover the alternative certipy-ad command well enough too
        $command_2 = " auth "
        $command_param_1 = "-ldap-shell"
        $subcommand_1 = "add_user_to_group "
        $subcommand_output_1 = "Adding user: "
        $subcommand_output_2 = " to group "
    condition:
        all of them
}