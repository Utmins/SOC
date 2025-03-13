#!/usr/bin/perl

use strict;
use warnings;
use diagnostics;

use Math::Round;

# Если число аргументов не равно единице
if (@ARGV != 1) {
        # Печатаем краткую справку
        print "Usage:\n";
        print "  $0 ifname\n\n";
        # Завершаем работу
        exit;
}

# Будем использовать полученные данные для очистки экрана в дальнейшем
my $clear_screen = `clear`;


# Получаем имя интерфейса
my $ifname = shift;

while (1) {
        # Сканируем эфир
        my $scan_result = `iwlist $ifname scan`;
        # Получаем код ошибки
        my $error_code = $?;
        # Завершаем работу если что-то не так
        exit if $error_code;
        # Наскорую руку разбиваем результат сканирования на элементы
        my @scan_results_tmp = split /Cell \d+/is, $scan_result;
        # Начинаем полноценный разбор
        my @scan_results = ();
        # Перебираем элементы
        foreach my $hotspot_line (@scan_results_tmp) {
                # Если нет номера канала значит это мусор, который надо пропустить
                next if $hotspot_line !~ m{Channel\:}is;
                # Строим элемент
                my %hotspot = ();
                # Номер канала
                $hotspot{'Channel'} = $hotspot_line;
                $hotspot{'Channel'} =~ s{^.+Channel\:(\d+).+$}{$1}is;
                # SSID
                $hotspot{'SSID'} = $hotspot_line;
                $hotspot{'SSID'} =~ s{^.+ESSID\:"((.+?)?)".+$}{$1}is;
                # Наличие шифрований
                $hotspot{'Crypted'} = $hotspot_line;
                $hotspot{'Crypted'} =~ s{^.+Encryption key:(\w+?)\s.+$}{$1}is;
                # Уровень сигнала. И сразу переводим его в проценты
                my $q1 = $hotspot_line;
                $q1 =~ s{^.+Quality=(\d+)/\d+.+$}{$1}is;
                my $q2 = $hotspot_line;
                $q2 =~ s{^.+Quality=\d+/(\d+).+$}{$1}is;
                $hotspot{'Quality'} = round($q1 * 100 / $q2);
                push @scan_results, \%hotspot;
        }
        # Сортируем
        @scan_results = sort { sprintf("%02d", $a->{Channel}) cmp sprintf("%02d", $b->{Channel}) } @scan_results;

        # Очищаем экран
        print $clear_screen;
        # Печатаем данные
        print sprintf("  % 2.2s [% 9.9s] [% 32.32s] [% 7.7s]\n", "Ch", "Quality", "SSID", "Crypt");
        print sprintf('%1$s'x61 . "\n", "-");
        foreach my $hotspot (@scan_results) {
                print sprintf("  %02d [% 8d%%] [% 32.32s] [% 7.7s]\n",
                        $hotspot->{Channel},
                        $hotspot->{Quality},
                        $hotspot->{SSID},
                        $hotspot->{Crypted});
        }
        # Делаем паузу
        sleep 1;
}