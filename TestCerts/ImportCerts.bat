certutil -f -addstore -user ROOT SslRsaRoot.cer
certutil -f -addstore -user CA SslRsaCA.cer
certutil -f -importPFX -p "openssl" -user My SslRsaServer.pfx
certutil -f -importPFX -p "openssl" -user My SslRsaClient.pfx
certutil -f -addstore -user My SslEccCA.cer
certutil -f -importPFX -p "openssl" -user My SslEccServer.pfx
certutil -f -importPFX -p "openssl" -user My SslEccClient.pfx
certutil -f -addstore -user ROOT SslEccRoot.cer
certutil -f -addstore -user My SslEccCA2.cer
certutil -f -importPFX -p "openssl" -user My SslEccServer2.pfx
certutil -f -importPFX -p "openssl" -user My SslEccClient2.pfx
certutil -f -importPFX -p "openssl" -user My SslEccServerClient.pfx