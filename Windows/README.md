#    BUILT-IN TOOLS
        -    Windows Security Tools
             Краткое описание основных процессов, связанных с безопасностью Windows (вместе с ссылка на детальные гайды):
                +    System
                +    Session Manager Subsystem (smss.exe) 
                +    Client Server Runtime Process (csrss.exe)
                +    Windows Initialization Process (wininit.exe)
                +    Service Control Manager / SCM (services.exe)
                +    Service Host (svchost.exe)
                +    Local Security Authority Subsystem Service (lsass.exe)
                +    Windows Logon (winlogon.exe)
                +    Windows Explorer (explorer.exe)
        
        -    SYSMON
            *  Весьма неплохие и детальные гайды:
                +    https://www.youtube.com/@TrustedSecTV/playlists
                +    https://github.com/jymcheong/SysmonResources  
            *    Сборники конфигурационных файлов, в которых можно найти различные идентификаторы:
                +    https://github.com/SwiftOnSecurity/sysmon-config/tree/master
                +    https://github.com/ion-storm/sysmon-config/tree/develop
                +    https://github.com/Neo23x0/sysmon-config
                +    https://github.com/trustedsec/SysmonCommunityGuide
                +    https://github.com/olafhartong/sysmon-modular
            *    Сборник по тестировке вашего конфиг-файла на различных угрозах
                +    https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/tree/master

        -    Windows Event Logs

        -    Event Tracing for Windows (ETW)

        -    Get-WinEvent by PowerShell        

#    3rd PARTY TOOLS
        -    OSQuery
            *    Официальный веб-сайт и github страница
                +    https://osquery.io/
                +    https://github.com/osquery/osquery
                +    https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/
            *    Полное описание всех компонентов OSQuery (но не факт, что все будут активны на исследуемой машине)
                +    https://osquery.io/schema/5.14.1/
            *    Гайд по SQL
                +    https://www.w3schools.com/sql/sql_intro.asp

        -    Sysinternals

        -    Wazuh

#    Credential Extraction


