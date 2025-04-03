#    DFIR General
     Общие сведения о том, что такое DFIR (Digital Forensics and Incident Response)
     Или другими словами    -    цифровая криминалистика и реагирование на инциденты.

#    Malware Analysis Basic
     Краткий обхор основных моментов, которые необходтмы для структырного анализа исполняемого (*.exe) зловреда

    -    Malware Databases and Samples
         Список ресурсов, которыя содержат либо информацию по зловреду, либо сами зловреды, либо песочницы для анализа

    -    Malware Analysis/Debugger Tools
         Список наиболее популярных инструментов для анализа зловреда, а именно reverse engineering

    -    Malware/Evidence Acquisition
         Утилиты , используемые для сбора следов активности зловреда, дампов памяти, образов лиска

    -    Anti-analysis techniques
         Методы используемые злоумышленниками в процессе создания исполняемого (*.exe) зловреда, которые позволяют ему обнаруживать тестируемую среду

    -    Executable Structure
         Структура внутренних компонентов исполняемого (*.exe) зловреда с точки зрения обратного инжениринга

#    Static Analysis (Linux and Windows)
     Описание различных утилит (tools), которые используют для первичного анализа исполняемого (*.exe) зловреда в той или иной ОС

    -    Linux
            *    file
            *    hexdump
            *    md5sum (sha256sum)
            *    imphash (это python-скрипт)
            *    pefile (это python-скрипт)
            *    pecheck (это python-скрипт)
            *    ssdeep
            *    string
            *    floss

    -    Windows
            *    Get-FileHash -Algorith <algorith_name> <C:\folder\where\you\keep\your\malware_samples\for_analysis\<file_name>.exe>
            *    imphash (это python-скрипт)
            *    pefile (это python-скрипт)
            *    pecheck (это python-скрипт)
            *    ssdeep
            *    string
            *    floss

#    Dynamic Analysis
     Описание принципов динамического анализа исполняемого (*.exe) зловреда
     А также его анализ на примере использования Python-скрипта для Sysinternals    -    Noriben

#    Code Analysis
     Общее пояснение по анализу кода исполняемого (*.exe) зловреда
     А так же упоминание за наиболее часто используемые утилиты для reverse engineering применяемые в disassembler and debugging исполняемого (*.exe) зловреда

    -    DisAssembler
            *    IDA
            *    Cutter
            *    Ghidra

    -    Debugging
            *    x32dbg / x64dbg
            *    OllyDbg
     PS. Структуру блоков кода зловреда можно найти в файле "Malware Analysis Basic"

#    IDA
     Обзор использования Disassembler утилиты    -    IDA
     Не только ее основных элементов
     Но и демонстрация на некоторых примерах

     При работате на виртуальной Windows машине, которая не подключена к интеренту, Вам потребуется следующая комнада для создания RDP-подключеня с общим каталогом

        <user_name>@<host_name>$ xfreerdp /u:<user_name> /p:<password> /v:<virtual_host_IP> /dynamic-resolution /drive:<share_name>,/path/to/the/folder/on/your/main/host

#    Debugging
     Обзор использования Disassembler утилиты    -    x64dbg
     Не только ее основных элементов
     Но и демонстрация на некоторых примерах

     Так же данный файл сожержит инструкцию по настройке и созданию эмитации интернет деятельности тестовой мащины с использованием InetSim
     
     
     
     
            

    
