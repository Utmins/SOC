#    Windows Forensic
        -    Registry
                *    https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives
                *    https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users
                *    https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/install-different-office-visio-and-project-versions-on-the-same-computer#office-releases-and-their-version-number

        -    Registry Viewer Tools
                *    https://www.exterro.com/
                *    https://ericzimmerman.github.io/#!index.md
                *    https://github.com/keydet89/RegRipper3.0

        -    Practise Hints
                *    Сожержит нюансы при работе некоторых утилис с образами для исследования

#    Linux Forensic
        -    Офийиальный гайд и различные мануалы
                *    https://crontab.guru/ (переводит на понятный язык временные настройки журнала crontab)

#    Memoory Forensic


#    Autopsy
        -    Офийиальный гайд и различные мануалы
                *    https://www.autopsy.com/
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ds_page.html (документация Autopsy, о других источниках данных, которые можно добавить в дело)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ingest_page.html (информация о модулях Ingest)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tree_viewer_page.html (информация о пользовательском интерфейсе)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tagging_page.html (информация о TAGах)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/reporting_page.html (информация об Reports)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/result_viewer_page.html (информация по Result Viewer)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/content_viewer_page.html (информация о Content Viewer)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/central_repo_page.html (информация о вкладке Central Repository)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ad_hoc_keyword_search_page.html (информация по Keyword Search)
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/uilayout_page.html (информация по Status Area)

        -    3rd Party Modules
                *    https://sleuthkit.org/autopsy/docs/user-docs/4.12.0/module_install_page.html
                *    https://github.com/sleuthkit/autopsy_addon_modules

        -    Pracise Case
                *    https://cfreds.nist.gov/

#    RedLine
        -    Офийиальный гайд и различные мануалы
                *    chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/https://fireeye.market/assets/apps/211364/documents/877936_en.pdf (основной мануал)
                *    https://fireeye.market/apps/S7cWpi9W (IoC Editor)
                *    https://fireeye.market/apps/211404 (OpenIoC 1.1 Editor)
                *    ttps://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf (IoC Пользовательский мануал)

#    KAPE (Kroll Artifact Parser and Extractor)
        -    Офийиальный гайд и различные мануалы
                *    https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape
                *    https://ericzimmerman.github.io/KapeDocs/#!Pages%5C5.-gkape.md (Eric Zimmerman tool)
                *    https://www.kroll.com/en/insights/publications/cyber/exploring-kapes-graphical-user-interface (мануал по графической версии)
                *    https://www.cadosecurity.com/blog/dfir-with-kape-and-cado-community-edition (3rd party мануал)

        -    Modules & Targets collection
                *    https://github.com/EricZimmerman/KapeFiles

#    Volatility
        -    Офийиальный гайд и различные мануалы
                *    https://github.com/volatilityfoundation/volatility/wiki
                *    https://github.com/volatilityfoundation/volatility/wiki/Volatility-Documentation-Project
        -    Различные модули, плагины и необходимые утилиты
                *    https://github.com/volatilityfoundation/volatility3/releases/tag/v1.0.1 (сама утилита)
                *    https://pypi.org/project/pefile/ (необходимый для работы модуль - PeFile)
                *    https://github.com/VirusTotal/yara-python (необходимый для работы модуль - Yara-Python)
                *    https://www.capstone-engine.org/download.html (необходимый для работы модуль - Capstone)
                *    https://github.com/volatilityfoundation/volatility3#symbol-tables (необходимый набор символов при работе из-под Linux/Mac)
                *    https://tools.kali.org/forensics/bulk-extractor (инструменты, для извлечения файл PCAP из файла памяти)

#    Velociraptor
        -    Офийиальный гайд и различные мануалы
                *    https://github.com/Velocidex/velociraptor/releases (исполняемый файл)
                *    https://docs.velociraptor.app/training/ (video guide)
                *    https://docs.velociraptor.app/docs/deployment/ (обычное развертывание)
                *    https://docs.velociraptor.app/docs/deployment/#instant-velociraptor (развертывание Instant версии)
                *    https://docs.velociraptor.app/docs/gui/#the-welcome-screen (admin GUI страница)
                *    https://docs.velociraptor.app/docs/gui/clients/ (Опрос/Interrogate хостов)
                *    https://docs.velociraptor.app/docs/gui/artifacts/ (артифакты)
                *    https://docs.velociraptor.app/docs/gui/vfs/ (VFS)
                *    https://docs.velociraptor.app/docs/vql/ (VQL основное)
                *    https://docs.velociraptor.app/docs/overview/#vql---the-velociraptor-difference (VQL отличительные моменты)
                *    https://docs.velociraptor.app/docs/vql/notebooks/ (notebooks)
                *    https://docs.velociraptor.app/docs/vql/artifacts/ (vql артифакты)
                *    https://docs.velociraptor.app/vql_reference/ (VQL reference)
                *    https://docs.velociraptor.app/docs/extending_vql/ (extrs VQl information)
                *    https://docs.velociraptor.app/docs/forensic/ (VQL forensic)

        -    Pracise Case
                *    https://docs.velociraptor.app/presentations/

#    The HIVE Project
        -    Офийиальный гайд и различные мануалы
                *    https://thehive-project.org/
                *    https://github.com/TheHive-Project/TheHive
                *    https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage (Traffic Light Protocol)

        -    Различные модули, плагины и необходимые утилиты
                *    https://github.com/TheHive-Project/Cortex/ (Cortex module)
                *    https://github.com/TheHive-Project/DigitalShadows2TH (DigitalShadows2TH  -  Digital Shadows Alert Feeder for TheHive)
                *    https://github.com/TheHive-Project/Zerofox2TH (Zerofox2TH  -  ZeroFOX Alert Feeder for TheHive)

#    Malware Analysis
        -     Различные мануалы и гайды
                *    https://zlib.net/ (библиотека сжатия данных zlib)

        -    Различные модули, плагины и необходимые утилиты
                *    https://github.com/cuckoosandbox/cuckoo (песочница Cuckoo)
                *    https://github.com/kevoreilly/CAPEv2 (песочница CAPE)
                *    https://cuckoo.cert.ee/ (онлайн песочница Cuckoo)
                *    https://any.run/ (онлайн песочница Any.run)
                *    https://analyze.intezer.com/ (онлайн песочница Intezer)
                *    https://hybrid-analysis.com/ (онлайн песочница Hybrid Analysis)

=====================================================================
#    Practise
        -    Autopsy
                *    Autopsy_Small Practise    (практическое задание по анализу образа диска)

        -    Windows Multitools
                *    DFIR Practise_Multitool 1 (практическое задание с использованием Registry Explorer / Autopsy / JLECmd / KAPE / EXViewer)
                *    Windows Registry Forensic_Small Practise (практическое задание с использованием Registry Explorer)

        -    Linux
                *    Linux_Samll Practise      (практическое задание в среде Linux)


