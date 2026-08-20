rule net_view {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1135"
    strings:
        $ = "net view"
    condition:
        any of them
}

rule portscan {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1046"
        tool_owner = "Fortra"
        tool_name = "Cobalt Strike"
        tool_url = "https://www.cobaltstrike.com/"
    strings:
        $ = "portscan" nocase
    condition:
        any of them
}

rule netGroupListMembers {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1069.002"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "netGroupListMembers"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $ = "netGroupListMembers"
    condition:
        any of them
}

rule ldapsearch {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1087.002"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "ldapsearch"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $ = "ldapsearch"
    condition:
        any of them
}

rule wmiquery {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1082"
        tool_name = "Impacket"
        tool_component = "wmiquery"
        tool_url = "https://github.com/fortra/impacket"
    strings:
        $ = "wmiquery.py"
        $ = "impacket-wmiquery"
    condition:
        any of them
}

rule cim_local_service_query {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1007"
        tool_name = "Powershell"
    strings:
        $ = "Get-CimInstance" nocase
        $ = " FROM Win32_Service" nocase
    condition:
        all of them
}

rule FindObjects {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1057"
        tool_name = "FindObjects"
        tool_url = "https://github.com/outflanknl/C2-Tool-Collection/tree/main/BOF/FindObjects"
    strings:
        $command_1 = "FindModule"
        $command_2 = "FindProcHandle"
    condition:
        any of them
}

rule nmap {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1046"
        tool_name = "nmap"
        tool_url = "https://nmap.org"
    strings:
        $command = "nmap "
        $output = "Starting Nmap "
    condition:
        any of them
}

rule schtasksquery {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1082"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "schtasksquery"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $bof_name = "schtasksquery"
    condition:
        any of them
}

rule reg_query {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1012"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "reg_query"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $bof_name = "reg_query"
    condition:
        any of them
}

rule netshares {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1135"
        tool_owner = "TrustedSec"
        tool_name = "Situational Awareness BOF"
        tool_component = "netshares"
        tool_url = "https://github.com/trustedsec/CS-Situational-Awareness-BOF"
    strings:
        $bof_name = "netshares"
    condition:
        any of them
}

rule nslookup {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1046"
    strings:
        $ = "nslookup"
    condition:
        any of them
}

rule adcs_enum {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1087.002"
    strings:
        $ = "adcs_enum"
    condition:
        any of them
}

rule volumiser_volumes {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1673"
        tool_name = "Volumiser"
        tool_url = "https://github.com/CCob/Volumiser"
    strings:
        $command_param = "volumes"
        $output = "[+] Opened disk image, Size: "
    condition:
        all of them
}

rule ps {
    meta:
        mitre_att_tactic = "TA0007"
        mitre_att_technique = "T1057"
    strings:
        $command = "ps"
        $output = "ppid" nocase
    condition:
        all of them
}
