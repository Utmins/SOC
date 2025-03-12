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
        -    Представлены несколько вариантов распространенных атак на среду Windows с целью кражи учетных данных с описанием как им противостоять:
            *    Kerberoasting
            *    AS-REProasting
            *    GPP Password
            *    GPO Permissions/GPO Files
            *    Credentials in Shares
            *    DCSync
            *    Golden Ticket
            *    Kerberos Constrained Delegation
            *    Print Spooler & NTLM Relaying
            *    Coercing Attacks & Unconstrained Delegation
            *    Object ACLs
            *    PKI-ESC1
            *    PKI-ESC8
            *    AD Certificate Service Abuse Techniques (pdf)

        -    Scripts
             А также несколько скриптов, которые используются в указанных выше атаках
                *    Dementor.py
                     Инструмент для атаки на Windows Print Spooler, используется для перехвата NTLM-хэшей
                     Эксплуатирует уязвимость в Windows Print Spooler (spoolss) для получения аутентификационных данных учетной записи машины.

                     Как работает:
                        +    Создает SMB-сервер для захвата NTLM-хэшей.
                        +    Использует MS-RPRN (Microsoft Remote Print Protocol) для открытия принтера на целевой системе.
                        +    Вызывает hRpcRemoteFindFirstPrinterChangeNotificationEx, чтобы заставить целевую систему аутентифицироваться на указанном сервере (listener).
                        +    Если все прошло успешно, сервер получит NTLM-хэш учетной записи машины, который затем можно попытаться расшифровать.

                    Использует библиотеки: impacket (smb, dcerpc, rprn), threading, argparse.

                *    ADACLScanner.ps1
                     Анализирует ACL (Access Control List) в Active Directory, выявляя потенциально уязвимые или избыточные разрешения.

                     Как работает:
                        +    Получает список объектов Active Directory.
                        +    Проверяет права доступа (Get-Acl) к этим объектам.
                        +    Фильтрует и отображает важные или подозрительные разрешения (например, WriteDacl, GenericAll).
                        +    Может использоваться для аудита безопасности AD и выявления потенциальных точек эскалации привилегий.

                *    GetAllDomainUserPermission.ps1
                     Получает список всех пользователей домена и их разрешений.

                     Как работает:
                        +    Использует Active Directory PowerShell-модули.
                        +    Запрашивает у контроллера домена данные обо всех пользователях (Get-ADUser).
                        +    Проверяет их разрешения (Get-ACL).
                        +    Выводит список пользователей с их правами на определенные объекты AD.

                *    SearchUserClearTextInformation.ps1
                     Ищет учетные данные и пароли в открытом виде (plaintext) в атрибутах пользователей Active Directory.

                     Как работает:
                        +    Запрашивает список пользователей через Get-ADUser.
                        +    Анализирует атрибуты (description, info, comment), где администраторы или пользователи могут случайно оставить пароли.
                        +    Фильтрует результаты и выводит пользователей, у которых найдены потенциально чувствительные данные.

                *    HoneypotGPOModificationAlert.ps1
                     Выполняет мониторинг событий изменения определенной GPO (Group Policy Object) и автоматически отключает учетные записи пользователей, которые внесли изменения.
                     Этот скрипт полезен для обнаружения и автоматического реагирования на несанкционированные изменения GPO в AD, что может указывать на попытки компрометации домена.
                     
                     Как работает:
                        +    Отслеживает изменения в "ловушечной" GPO (Honeypot GPO).
                        +    Выявляет пользователей, которые внесли изменения.
                        +    Автоматически блокирует их учетные записи в Active Directory.
                        +    Формирует отчет о сработавшей защите.
             

