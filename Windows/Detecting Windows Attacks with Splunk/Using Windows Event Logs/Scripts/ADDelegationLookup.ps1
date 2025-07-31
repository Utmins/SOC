<#
.SYNOPSIS
    Получение информации о делегации в AD.

.DESCRIPTION
    Скрипт выполняет два запроса:
    1. Ищет компьютеры с TrustedForDelegation и PrimaryGroupId 515.
    2. Ищет объекты в AD с установленным атрибутом msDS-AllowedToDelegateTo.

.NOTES
    Требуется модуль ActiveDirectory.
#>

# Проверка наличия модуля ActiveDirectory
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Модуль ActiveDirectory не установлен. Установите RSAT или выполните скрипт с контроллера домена."
    exit
}

# Импорт модуля
Import-Module ActiveDirectory

Write-Host "`n=== Компьютеры с Unconstrained Delegation ===" -ForegroundColor Cyan
$UnconstrainedDelegatedObjects = Get-ADComputer -Filter {
    TrustedForDelegation -eq $true -and PrimaryGroupId -eq 515
} -Properties TrustedForDelegation, ServicePrincipalName, Description

$UnconstrainedDelegatedObjects | Select-Object Name, Description, TrustedForDelegation, ServicePrincipalName | Format-Table -AutoSize

Write-Host "`n=== Объекты с Constrained Delegation (msDS-AllowedToDelegateTo) ===" -ForegroundColor Cyan
$ConstrainedDelegatedObjects = Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo, Name, ObjectClass

$ConstrainedDelegatedObjects | Select-Object Name, ObjectClass, msDS-AllowedToDelegateTo | Format-Table -AutoSize

# Необязательное сохранение результатов
# $UnconstrainedDelegatedObjects | Select Name, Description, TrustedForDelegation, ServicePrincipalName | Export-Csv "delegated_computers.csv" -NoTypeInformation -Encoding UTF8
# $ConstrainedDelegatedObjects | Select Name, ObjectClass, msDS-AllowedToDelegateTo | Export-Csv "objects_with_allowedtodelegateto.csv" -NoTypeInformation -Encoding UTF8
