Set-StrictMode -Version Latest
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $PSScriptRoot "..")
python .\eml_attch_analyzer.py .\examples\sample.eml --algo sha256,md5
