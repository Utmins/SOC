#    Common Tools
        -    Brim
             Это графический интерфейс для анализа сетевых логов, особенно логов, полученных от Zeek или Suricata.

                *    Позволяет быстро обрабатывать большие объемы данных (PCAP-файлы, Zeek-логи) и применять фильтры для поиска подозрительной активности.
                *    Основан на языке запросов Zed, который помогает структурировать и анализировать трафик.
                *    Может экспортировать данные для дальнейшего анализа в Wireshark или других инструментах.
            
             Использование:

                *    Анализ сетевого трафика на предмет аномалий.
                *    Быстрый просмотр больших логов без необходимости загрузки PCAP в Wireshark.
                *    Расследование инцидентов кибербезопасности.

        -    NetworkMiner
             Утилита для пассивного анализа трафика и извлечения артефактов из PCAP-файлов.

                *    Позволяет извлекать файлы, учетные данные, изображения, DNS-запросы и другие артефакты из захваченного трафика.
                *    Поддерживает работу без активного вмешательства в сеть (в отличие от Wireshark).

             Использование:

                *    Анализ сетевых атак и утечек данных.
                *    Извлечение файлов из зашифрованного трафика (если TLS-декрипция разрешена).
                *    Определение атакующих IP-адресов и вредоносного ПО в трафике.

        -    Wireshark
             Один из самых популярных инструментов для анализа сетевых пакетов.

                *    Позволяет просматривать, фильтровать и анализировать трафик в реальном времени или из PCAP-файлов.
                *    Поддерживает более 2000 сетевых протоколов, включая HTTP, TLS, DNS, SMB, FTP и другие.
                *    Включает мощные графические и текстовые фильтры для детального анализа трафика.
    
             Использование:

                *    Тестирование сетевой безопасности (например, обнаружение нешифрованных данных).
                *    Анализ производительности сети и диагностика сбоев.
                *    Исследование вредоносного трафика и взломов

        -    Zeek
             Мощный сниффер трафика, который анализирует сетевые пакеты и создает детализированные логи сетевой активности.
             Отличается от Wireshark тем, что не просто фиксирует пакеты, а анализирует их на более высоком уровне (HTTP, DNS, TLS, FTP, SMB и т. д.).

                *    Может автоматически выявлять аномалии в трафике и передавать события в SIEM-системы.

             Использование:

                *    Сетевой мониторинг и анализ угроз (DDoS, аномалии в поведении пользователей).
                *    Расследование инцидентов безопасности и сетевых атак.
                *    Логирование сетевой активности для форензики.

        -    TShark
             Это консольная версия Wireshark, позволяющая захватывать и анализировать пакеты в реальном времени.

                *    Может фильтровать пакеты на лету, а также сохранять захваченный трафик для дальнейшего анализа.
                *    Поддерживает BPF-фильтры и Wireshark Display Filters.
            
             Использование:

                *    Захват трафика на удаленных серверах без GUI.
                *    Анализ сетевой активности в режиме командной строки.
                *    Автоматический мониторинг трафика в скриптах.

============================================================================================

Следующие каталоги содержат файлы с описанием методов обнаружения развличных типов сетевых атак (с использованием WireShark)

#    Link Layer Scan & Defense
         Данные примеры направлены на демонстрацию:
            -    Обнаружения уязвимостей на основе ARP, включая спуфинг, сканирование и атаки типа «отказ в обслуживании».
            -    Понимание угроз 802.11, включая отказ в обслуживании и деаутентификацию.
            -    Стратегии выявления и смягчения последствий несанкционированных точек доступа и вредоносных атак «Evil-Twin».

         Вот одни из основных типов данных атак и способы их обнаружения:

            -    ARP Spoofing & Abnormality Detection
            -    ARP Scanning & Denial-of-Service
                 Протокол разрешения адресов (ARP) используется злоумышленниками для запуска различного рода атака, таки как
                    сбор информации о сети
                    атак типа «человек посередине»
                    атака типа «отказ в обслуживании».

            -    802.11 Denial of Service
                 Данный тип атаки направлен на 802.11 (Wi-Fi)
                 Другими словами - атака деаутентификации/диссоциации

                 *** Для сканирования Wi-Fi эфира, чтобу узнать какие беспроводные сети активны в данный момент, можно использовать скрипт - wifi_scan.pl

            -    Rogue Access Point & Evil-Twin Attacks
                 Атаки направленные на проникновение в сеть жертвы путем установки незарегистрированной точки доступа внутри сети (Rogue Access Point)
                 Или для иммитации легитимной точки доступа с цель прослушивания и/или кражи трафика (Evil-Twin)
         

#    Detecting Network Abnormalities
         Данные примеры направлены на демонстрацию:
            -    Методов обнаружения атак фрагментации и намерений, стоящих за подменой IP.
            -    Обнаружение нарушений TCP-рукопожатия и аномалий подключения, таких как сброс и перехват.
            -    Раскрытие скрытых каналов, таких как туннелирование ICMP.

         Вот одни из основных типов данных атак и способы их обнаружения:

            -    Fragmentation Attack
                 По своей сути, злоумышленники могут создавать/изменять пакеты, чтобы вызывать проблемы со связью.
                 Традиционно злоумышленник может попытаться обойти контроль IDS посредством искажения или модификации пакетов, т.е. разделение всего пересылаемого сообщения на части

            -    IP Source & Destination Spoofing Attacks
                 Злоумышленник может проводить эти атаки по созданию пакетов в направлении source and destination IP-адресов по разным причинам или для достижения желаемых результатов.
                 Вот несколько из них:
                    Decoy Scanning (Ложное сканирование)
                    DDoS-атака случайного источника
                    Атаки LAND
                    Атаки SMURF
                    Initialization Vector Generation

            -    IP Time-to-Live Attacks
                 Атаки Time-to-Live в основном используются злоумышленниками как средство уклонения.
                 По сути, злоумышленник намеренно устанавливает очень низкий TTL для своих IP-пакетов, чтобы попытаться обойти межсетевые экраны, системы IDS и IPS.

            -    TCP Handshake Abnormalities
                 Тип атаки при которой осуществляется различные манипуляции с флагами TCP пакета либо для обхода защиты, либо для сбора информации

            -    TCP Connection Resets & Hijacking
                 Тип атаки при которой осуществляется разрым TCP соединения для дальнейшего его перехвата

            -    ICMP Tunneling
                 Туннелирование — это метод, используемый злоумышленниками для перекачки данных из одного места в другое.
                 Этот тип атаки демоснтрирует использование анамального количества ICMP-пакетов для передачи украденной информации или пересылки команд с C2 сервера
                 

#    Application Layer Attack & Deffence
         Данные примеры направлены на демонстрацию:
            -    Обнаружения веб-угроз из перечисления HTTP/HTTPS и странностей в заголовках HTTP.
            -    Выявления и противодействия атакам с внедрением, таким как XSS и внедрение команд, а также скрытым атакам с повторным согласованием SSL.
            -    Стратегии выявления подозрительных действий DNS и необычных подключений Telnet и UDP.

         Вот одни из основных типов данных атак и способы их обнаружения:

            -    HTTP&HTTPs Service Enumeration
                 Генерирация избыточного трафик с HTTP или HTTP для осуществления различных атака
                 К примеру таких как:
                    Фаззирование, т.е. осуществление множества одновременных и различных запросов либо для взлома, либо для эксфильрации (как правило посредством использования Burp Suite)

            -    Strange HTTP Headers
                 Если анализ фаззирования ничего не дал, то стоит исследовать заголовки пакетов на предмет аномалий
                 К примеру таких как:
                        Странные хосты
                        Необычные HTTP-глаголы
                        Измененные пользовательские агенты (User Agents)

            -    Cross-Site Scripting (XSS) & Code Injection Detection
                 Внедрение вредоносного кода для кражи данных/cookies или для дальнейшего проникновения, так как веб-ресурсы не содержали необходимого code-sanitizing

            -    SSL Renegotiation Attacks
                 Использование уязвимости SSL для взлома зашифрованных HTTPS сообщений
                 
            -    Peculiar DNS Traffic
                 Использование DNS пакетов для:
                    Эксфильтрация данных
                    Управление и контроль
                    Обход брандмауэров и прокси-серверов
                    Domain Generation Algorithms

            -    Strange Telnet & UDP Connections
                 Использование TELNET протокола для различных манипуляций

#    Scripts
         Каталог различных скриптов помогающих при анализе той или иной проблемы/задачи
            -    wif_scan.pl    -    скрипт, написанный на Perl, который используется для прослушивания и определения доступных wifi устройств 
