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
