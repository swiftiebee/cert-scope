# Сборка и тесты

Из корня проекта запустите в Windows PowerShell 5.1:

```powershell
.\tools\prepare.ps1
.\build.ps1 -Test
```

Первая команда загружает опорные сборки .NET Framework 4.5 из NuGet. Вторая собирает приложение, компилирует и запускает тесты. Результаты находятся в `artifacts/test-results.txt`, новая сборка — в `artifacts/CertScope.exe`. Для сборки без тестов запустите `.\build.ps1`. Для путей сборки на .NET Framework 4.5 удобен короткий путь к рабочей копии, например `C:\CertScope`.

## Сетевой тест

Подготовьте цель по [сетевой инструкции](target-setup.md). Со сканера проверьте чтение того же хранилища теми же учётными данными:

```powershell
.\tests\network-preflight.ps1 -ComputerName 'CERT-TARGET' -RegistryBranches 'HKLM\SOFTWARE\Microsoft\SystemCertificates\MY' -AlternateCredential
```

Скрипт запрашивает сетевую учётку и создаёт отчёт `verification/network-preflight.json`. После этого запустите пробное сканирование в CertScope.

## Тест SQL

После сборки укажите отдельную существующую пустую БД SQL Server 2019. Тест создаёт таблицы и оставляет в БД тестовые записи.

```powershell
.\tests\sql-integration.ps1 -ServerInstance 'localhost' -ExistingTestDatabase 'CertScopeTest'
```
