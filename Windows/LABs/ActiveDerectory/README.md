# Campfire 1 (Kerberoasting Detection in Active Directory)

Сценарий описывает расследование возможной атаки Kerberoasting в инфраструктуре Windows Active Directory. SOC получил сообщение от сотрудника о подозрительных файлах на рабочей станции, что привело к анализу журналов контроллера домена (Security-DC.evtx), PowerShell-логов затронутой станции (Powershell-Operational.evtx) и Prefetch-файлов.

Основные задачи:
  -  определить время атаки (по событиям 4648, 4624/4625, 4768, 4769)$
  -  идентифицировать сервис, ставший целью$
  -  установить IP-адрес атакующей станции$
  -  выявить PowerShell-скрипт для перечисления учетных записей и время его запуска$
  -  а также определить утилиту Kerberoasting по Prefetch-записям и момент её запуска.

Подчёркивается необходимость перекрёстной проверки улик из разных источников и привязка техники к MITRE.

Журналы и артефакты:

    -  Security-DC.evtx — события Kerberos (4768/4769), входы (4624/4625), явные учетные данные (4648).
    -  Powershell-Operational.evtx — Scriptblock Logging (4104), фиксация запуска PowerShell-скриптов.
    -  Prefetch-файлы — следы запуска утилит Kerberoasting.

Инструменты:

    -  EvtxECmd — конвертация EVTX для анализа.
    -  PECmd — анализ Prefetch.
    -  Timeline Explorer — гибкая фильтрация и навигация по CSV.
    -  Event Viewer — стандартный просмотрщик Windows-логов.
    -  Splunk — индексация и визуализация событий.

# Campfire 2 (AS-REP Roasting Investigation)

Сценарий посвящён расследованию возможного AS-REP Roasting-инцидента в инфраструктуре Windows Active Directory: обнаружено подозрительное поведение старой учётной записи без включённой предварительной аутентификации, что даёт злоумышленнику возможность запросить AS-REP и получить ответ, зашифрованный ключом, производным от пароля целевой учётки.

Задача аналитика:
  - подтвердить факт атаки по журналам контроллера домена
  - установить временные границы активности
  - идентифицировать целевую учётную запись и её SID
  - найти внутренний источник запросов (IP) и проверить, не последовало ли боковое смещение или дальнейшая компрометация сервисов/пользователей.

Руководство даёт практические шаги по фильтрации событий (4768/4769 и сопутствующие), анализу полей TicketEncryptionType, TargetUserName, TargetSid и IpAddress, а также по использованию TimelineExplorer / EvtxEcmd / Event Viewer для надёжной верификации находок. 

Журналы и артефакты:

    - Security.evtx — первоочередной источник;
    - ключевые события: Event ID 4768 (запрос TGT), Event ID 4769 (запрос TGS) и события входа 4624/4625 для контекста;
    - поля TicketEncryptionType, TargetUserName, TargetSid, IpAddress и TimeCreated — критичны для подтверждения AS-REP Roasting. 

Инструменты:

    - EvtxEcmd — конвертация EVTX в CSV/JSON для последующей фильтрации.
    - Timeline Explorer — корреляция по времени, фильтрация по полям и удобная привязка TimeCreated.
    - Event Viewer — быстрый просмотр записей и извлечение EventData (TargetUserName/TargetSid/IpAddress).

# Noxious (LLMNR poisoning / NetBIOS spoofing investigation)

Сценарий описывает расследование инцидента LLMNR/NBT-NS poisoning, когда внутренний хост отправил имя сервера по сети и злоумышленник в локальной сети ответил на запрос, перехватив аутентификационные попытки и собрав NTLM-артефакты. В качестве исходного источника используются сетевые дампы (pcap), содержащие LLMNR/NetBIOS-ответы, DHCP/NetBIOS/SMB обмены и NTLMSSP-сессии. Аналитик должен восстановить цепочку: кто отправил запрос, кто ответил, какие учётные данные были перехвачены и были ли предприняты последующие попытки доступа к ресурсам.

Руководство даёт практические шаги по фильтрации NTLM событий c использованием  Wireshark и Tsahrk, анализу пакетов сетевого трафика, а также по использованию утилит для взлома NTLM-хешей паролей.

Задача аналитика:
  - Определить временные границы инцидента и зафиксировать номера ключевых пакетов (UTC-времена, packet IDs)
  - Выявить IP/MAC/hostname устройства-атакующего (через LLMNR/NetBIOS/DHCP/ARP)
  - Извлечь NTLM-артефакты (NTLMSSP_CHALLENGE, NTProofStr, NTLMv2 Response) и username/domain жертвы
  - Подготовить корректный вход для cracking (формат для hashcat/john) и оценить вероятность успешного брутфорса
  - Проверить последующие SMB/IPC активности (попытки доступа к шарам, lateral movement)
  - Собрать IOC (IP, MAC, hostnames, usernames, хеши, packet IDs, временные метки) для передачи в SIEM/блок-лист

Журналы и артефакты:

    - capture.pcap — основной исходный дамп (LLMNR, NetBIOS, DHCP, ARP, SMB, NTLMSSP)
    - поля NTLM (Server Challenge, NTProofStr, NTLMv2 Response) — для формирования записи для cracking
    - DHCP Option 12 / NetBIOS Name / SMB negotiate — hostname и признаки несоответствия неймингу
    - MAC-адреса и ARP — физическая идентификация устройства-ответчик

Инструменты:

    - Wireshark — интерактивный разбор (фильтры llmnr, nbns, ntlmssp, smb2), извлечение полей NTLM
    - tshark — скриптовые выборки и экспорт пакетов (tshark -r capture.pcap -Y 'ntlmssp' -w ntlm_sessions.pcap)
    - hashcat / john — проверка NTLMv2 ответов (режимы для NetNTLMv2/5600 и т.п.)
  
# Reaper (NTLM Relay Investigation)

Данный сценарий — практическое руководство по расследованию NTLM-relay атаки в среде Windows/Active Directory. На основе сетевого дампа ntlmrelay.pcapng и журнaла Security.evtx аналитик восстанавливает цепочку: кто перехватил NTLM-запрос, какие артефакты (IP address, port #, username/domain) были собраны, какие ресурсы атакующий пытался использовать (SMB shares, IPC$ и т.п.) и привязывает это к событиям входа в Security.evtx. 

Задача аналитика:
  - Зафиксировать временные метки и packet IDs ключевых пакетов (NTLM/SMB/LLMNR/DHCP) и связать их с EventID в Security.evtx.
  - Выявить IP/MAC/порт и hostname атакующего узла и подтвердить его роль через DHCP/ARP/NetBIOS/LLMNR ответы.
  - Определить, какие общедостпнве ресурсы были целью ретрансляции (например \\DC01\Trip, IPC$), и проверить факт доступа/перемещения.
  - Сформировать IOCs (IP, MAC, port, hostnames, usernames, hashes, packet IDs, UTC timestamps)

Журналы и артефакты:

    - ntlmrelay.pcapng — сетевой дамп с LLMNR/NBNS/SMB/NTLM пакетов; источник packet IDs и сетевых артефактов.
    - Security.evtx — Windows Security логи (EventID 4624/4625/4648 и др.) — для подтверждения входов и привязки LogonID к сетевому трафику.

Инструменты:

    - Wireshark, tshark — интерактивный и скриптовый разбор pcap (фильтры: ntlmssp, smb2, llmnr, nbns, dhcp).
    - EvtxEcmd / Timeline Explorer / Event Viewer — парсинг EVTX и корреляция событий.
