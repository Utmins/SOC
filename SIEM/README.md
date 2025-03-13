#    IDS & IPS
        -    Basics of IDS & IPS
        
        -    Suricata:
                +    Гайды, мануалы, инструкции, статьи
                    *    https://docs.suricata.io/en/latest/ (официальный гайд)                    
                    *    https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Protocol_Anomalies_Detection (стратегии)
                    *    https://suricata.readthedocs.io/en/latest/rules/http-keywords.html (гайд по Rules Buffer)
                    *    https://docs.suricata.io/en/latest/rules/index.html (гайд по разработке правил)
                    *    https://wiki.osdev.org/MZ (MZ, a.k.a. MS-DOS EXE сигнатуры для бинарного определния формата)
                +    PowerShell Empire
                    *    https://github.com/EmpireProject/Empire/blob/master/data/agent/agent.ps1#L78 (PowerShell Empire agent для правил Suricata)
                    *    https://www.keysight.com/blogs/tech/nwvs/2021/06/16/empire-c2-networking-into-the-dark-side (PowerShell Empire статья относительно cookies и их кодировке в base64)
                +    Covenant            
                    *    https://petruknisme.medium.com/getting-started-with-covenant-c2-for-red-teaming-8eeb94273b52 (Covenant)
                    *    https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Profiles/DefaultHttpProfile.yaml#L35 (Covenant)
                    *    https://repositorio-aberto.up.pt/bitstream/10216/142718/2/572020.pdf (Техника обнаружения Covenant)
                +    Sliver            
                    *    https://barrymalone.medium.com/sliver-an-awesome-c2-framework-c0257f2f52e4 (Sliver)
                    *    https://github.com/BishopFox/sliver (Sliver)
                    *    https://github.com/BishopFox/sliver/blob/master/server/configs/http-c2.go#L294 (Sliver)
                    *    https://www.bilibili.com/read/cv19510951/ (Техника обнаружения Sliver, но к сожалению на китайском)
                +    Dridex            
                    *    https://unit42.paloaltonetworks.com/wireshark-tutorial-dridex-infection-traffic/ (Dridex)

        -    SNORT
                +    Гайды, мануалы, инструкции, статьи
                    *    https://docs.snort.org/ (официальный гайд)
                    *    https://docs.suricata.io/en/latest/rules/differences-from-snort.html (гайд по правилам)
                    *    https://community.emergingthreats.net/ (самые последние правила для Snort)
                    
#    General Tools
        -    Elastic (ELK)
                +    Весьма неплохие (детальные) гайды и официальный сайт:
                    *    https://www.elastic.co/elastic-stack  
                +    Сборники конфигурационных файлов, в которых можно найти различные идентификаторы:
                    *    https://www.elastic.co/guide/en/logstash/8.1/input-plugins.html
                    *    https://www.elastic.co/guide/en/logstash/8.1/filter-plugins.html
                    *    https://www.elastic.co/guide/en/logstash/8.1/output-plugins.html
                    *    https://www.elastic.co/guide/en/kibana/7.17/kuery-query.html

        -    Splunk
                +    Весьма неплохие (детальные) гайды и официальный сайт:
                    *    https://www.splunk.com/
                    *    https://splunkbase.splunk.com/
                    *    https://docs.splunk.com/Documentation/Splunk/8.1.2/SearchTutorial/NavigatingSplunk
                    *    https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Metadata
                    *    https://www.splunk.com/en_us/blog/security/metadata-tstats-threat-hunting.html?301=/blog/2017/07/31/metadata-metalore.html
                    *    https://docs.splunk.com/Documentation/SCS/current/SearchReference/Introduction
                    *    https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/
                    *    https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/

        -    Practise
                +    Splunk
                    *    Splunk_Small Practise (hints)    -  объяснение (с примерами) некоторых, частоиспользуемых поисковых команд
                    *    Splunk_Small Practise (shorts)   -  варианты поска/обнаружения определенных событий
                    *    Splunk_Small Practise (full)     -  практическое задание по вывлению источника взлома сайта с использованием Cyber Kill Chain
                    *    Splunk_Small Practise (real)     -  наиболее преближенное к реальной жизни практическое задание по выявлению вредоносного файла, загруженного из интернета
                    *    Splunk_Small Practise (ID)       -  практическое задание по выявлению событий связанных с Intrusion Detection, а также настройка оповещений от вредоносных программ на основе вызовов API из НЕИЗВЕСТНЫХ областей памяти

                +    Elastic (ELK)
                    *    Elastick (ELK)_Small Practise        -    пособие по созданию dashboards (визуализаций)
                    *    Elastic (ELK)_Real Case Practise     -    пратическое задание на реальном событии по поиску последствий посещений фишинговой ссылки

#    Network Traffic Analysis
        -    Application Layer A&D
                +    ARP Spoofing & Abnormality Detection
                +    ARP Scanning & Denial-of-Service
                +    802.11 Denial of Service
                +    Rogue Access Point & Evil-Twin Attacks

