rule evil_winrm {
    meta:
        mitre_att_tactic = "TA0008"
        mitre_att_technique = "T1021.006"
        tool_name = "Evil-WinRM"
        tool_url = "https://github.com/Hackplayers/evil-winrm"
    strings:
        $ = "evil-winrm"
    condition:
        any of them
}

rule powershell_entersession {
    meta:
        mitre_att_tactic = "TA0008"
        mitre_att_technique = "T1021.006"
        tool_name = "PowerShell"
    strings:
        $ = "enter-pssession" nocase
        $ = " -computername " nocase
    condition:
        all of them
}

rule evil_winrm_upload {
    meta:
        mitre_att_tactic = "TA0008"
        mitre_att_technique = "T1570"
        tool_name = "Evil-WinRM"
        tool_url = "https://github.com/Hackplayers/evil-winrm"
        description = "Upload {{upload_info.2}} to {{upload_info.4}}:{{upload_info.5}} using Evil-WinRM"
    strings:
        $upload_info = /Info: Uploading .+ to .+/
        $upload_status = /Data: \d+ bytes of \d+ bytes copied/
    condition:
        all of them
}

rule smbexec {
    meta:
        mitre_att_tactic = "TA0008"
        mitre_att_technique = "T1021.002"
        tool_name = "Impacket"
        tool_component = "smbexec"
        tool_url = "https://github.com/fortra/impacket"
        description = "Start interactive {{#shell_param.1}}{{shell_param.1}} {{/shell_param.1}}shell via SMB IPC calls{{#service_param.1}} using new service named {{service_param.1}}{{/service_param.1}}"
    strings:
        $command_1 = "smbexec.py"
        $command_2 = "impacket-smbexec"
        $shell_param = /-shell-type \S+/
        $service_param = /-service-name \S+/
    condition:
        1 of ($command_1, $command_2) and #shell_param >= 0 and #service_param >= 0
}
