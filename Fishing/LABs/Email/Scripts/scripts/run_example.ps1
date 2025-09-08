Set-StrictMode -Version Latest
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $PSScriptRoot "..")
python .\eml_safe_hash_algo_pw.py .\examples\sample.eml --algo sha256,md5
