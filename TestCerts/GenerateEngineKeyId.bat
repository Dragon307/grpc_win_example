echo|set /p="engine:e_ncrypt:user:my:" > SslRsaServer.thumbprint
certutil -dump SslRsaServer.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslRsaServer.thumbprint

echo|set /p="engine:e_ncrypt:user:my:" > SslRsaClient.thumbprint
certutil -dump SslRsaClient.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslRsaClient.thumbprint

echo|set /p="engine:e_ncrypt:user:my:" > SslEccServer.thumbprint
certutil -dump SslEccServer.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslEccServer.thumbprint


echo|set /p="engine:e_ncrypt:user:my:" > SslEccClient.thumbprint
certutil -dump SslEccClient.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslEccClient.thumbprint

echo|set /p="engine:e_ncrypt:user:my:" > SslEccServer2.thumbprint
certutil -dump SslEccServer2.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslEccServer2.thumbprint


echo|set /p="engine:e_ncrypt:user:my:" > SslEccClient2.thumbprint
certutil -dump SslEccClient2.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslEccClient2.thumbprint


echo|set /p="engine:e_ncrypt:user:my:" > SslEccServerClient.thumbprint
certutil -dump SslEccServerClient.cer | findstr /C:"Cert Hash(sha1)" | for /f "tokens=3" %f in ('more') do @echo %f >> SslEccServerClient.thumbprint
