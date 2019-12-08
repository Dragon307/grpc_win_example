certreq -f -new SslRsaRoot.inf SslRsaRoot.csr
certutil -f -store -user My SslRsaRoot SslRsaRoot.cer
certutil -f -addstore -user ROOT SslRsaRoot.cer
openssl x509 -inform der -in SslRsaRoot.cer -out SslRsaRoot.pem
certutil -f -exportPFX -p "openssl" -user My SslRsaRoot SslRsaRoot.pfx
openssl pkcs12 -password pass:openssl -in SslRsaRoot.pfx -out SslRsaRoot.pem2 -nokeys
openssl x509 -in SslRsaRoot.pem2 -out SslRsaRoot.pem3
openssl pkcs12 -password pass:openssl -in SslRsaRoot.pfx -out SslRsaRoot.key2 -nodes -nocerts
openssl rsa -in SslRsaRoot.key2 -out SslRsaRoot.key
dir SslRsaRoot.*


certreq -f -new -q -cert "SslRsaRoot" SslRsaCA.inf SslRsaCA.csr
certutil -f -store -user My SslRsaCA SslRsaCA.cer
openssl x509 -inform der -in SslRsaCA.cer -out SslRsaCA.pem
certutil -f -exportPFX -p "openssl" -user My SslRsaCA SslRsaCA.pfx
openssl pkcs12 -password pass:openssl -in SslRsaCA.pfx -out SslRsaCA.pem2 -nokeys
openssl x509 -in SslRsaCA.pem2 -out SslRsaCA.pem3
openssl pkcs12 -password pass:openssl -in SslRsaCA.pfx -out SslRsaCA.key2 -nodes -nocerts
openssl rsa -in SslRsaCA.key2 -out SslRsaCA.key
dir SslRsaCA.*

certreq -f -new -q -cert "SslRsaCA" SslRsaServer.inf SslRsaServer.csr
certutil -f -store -user My SslRsaServer SslRsaServer.cer
openssl x509 -inform der -in SslRsaServer.cer -out SslRsaServer.pem
certutil -f -exportPFX -p "openssl" -user My SslRsaServer SslRsaServer.pfx
openssl pkcs12 -password pass:openssl -in SslRsaServer.pfx -out SslRsaServer.pem2 -nokeys
openssl x509 -in SslRsaServer.pem2 -out SslRsaServer.pem3
openssl pkcs12 -password pass:openssl -in SslRsaServer.pfx -out SslRsaServer.key2 -nodes -nocerts
openssl rsa -in SslRsaServer.key2 -out SslRsaServer.key
cmd /c copy SslRsaServer.pem+SslRsaCA.pem+SslRsaRoot.pem SslRsaServer.chain
dir SslRsaServer.*

certreq -f -new -q -cert "SslRsaCA" SslRsaClient.inf SslRsaClient.csr
certutil -f -store -user My SslRsaClient SslRsaClient.cer
openssl x509 -inform der -in SslRsaClient.cer -out SslRsaClient.pem
certutil -f -exportPFX -p "openssl" -user My SslRsaClient SslRsaClient.pfx
openssl pkcs12 -password pass:openssl -in SslRsaClient.pfx -out SslRsaClient.pem2 -nokeys
openssl x509 -in SslRsaClient.pem2 -out SslRsaClient.pem3
openssl pkcs12 -password pass:openssl -in SslRsaClient.pfx -out SslRsaClient.key2 -nodes -nocerts
openssl rsa -in SslRsaClient.key2 -out SslRsaClient.key
cmd /c copy SslRsaClient.pem+SslRsaCA.pem+SslRsaRoot.pem SslRsaClient.chain
dir SslRsaClient.*

certreq -f -new -q -cert "SslRsaRoot" SslEccCA.inf SslEccCA.csr
certutil -f -store -user My SslEccCA SslEccCA.cer
openssl x509 -inform der -in SslEccCA.cer -out SslEccCA.pem
certutil -f -exportPFX -p "openssl" -user My SslEccCA SslEccCA.pfx
openssl pkcs12 -password pass:openssl -in SslEccCA.pfx -out SslEccCA.pem2 -nokeys
openssl x509 -in SslEccCA.pem2 -out SslEccCA.pem3
openssl pkcs12 -password pass:openssl -in SslEccCA.pfx -out SslEccCA.key2 -nodes -nocerts
openssl ec -in SslEccCA.key2 -out SslEccCA.key
dir SslEccCA.*

certreq -f -new -q -cert "SslEccCA" SslEccServer.inf SslEccServer.csr
certutil -f -store -user My SslEccServer SslEccServer.cer
openssl x509 -inform der -in SslEccServer.cer -out SslEccServer.pem
certutil -f -exportPFX -p "openssl" -user My SslEccServer SslEccServer.pfx
openssl pkcs12 -password pass:openssl -in SslEccServer.pfx -out SslEccServer.pem2 -nokeys
openssl x509 -in SslEccServer.pem2 -out SslEccServer.pem3
openssl pkcs12 -password pass:openssl -in SslEccServer.pfx -out SslEccServer.key2 -nodes -nocerts
openssl ec -in SslEccServer.key2 -out SslEccServer.key
cmd /c copy SslEccServer.pem+SslEccCA.pem+SslRsaRoot.pem SslEccServer.chain
dir SslEccServer.*


certreq -f -new -q -cert "SslEccCA" SslEccClient.inf SslEccClient.csr
certutil -f -store -user My SslEccClient SslEccClient.cer
openssl x509 -inform der -in SslEccClient.cer -out SslEccClient.pem
certutil -f -exportPFX -p "openssl" -user My SslEccClient SslEccClient.pfx
openssl pkcs12 -password pass:openssl -in SslEccClient.pfx -out SslEccClient.pem2 -nokeys
openssl x509 -in SslEccClient.pem2 -out SslEccClient.pem3
openssl pkcs12 -password pass:openssl -in SslEccClient.pfx -out SslEccClient.key2 -nodes -nocerts
openssl ec -in SslEccClient.key2 -out SslEccClient.key
cmd /c copy SslEccClient.pem+SslEccCA.pem+SslRsaRoot.pem SslEccClient.chain
dir SslEccClient.*


certreq -f -new SslEccRoot.inf SslEccRoot.csr
certutil -f -store -user My SslEccRoot SslEccRoot.cer
certutil -f -addstore -user ROOT SslEccRoot.cer
openssl x509 -inform der -in SslEccRoot.cer -out SslEccRoot.pem
certutil -f -exportPFX -p "openssl" -user My SslEccRoot SslEccRoot.pfx
openssl pkcs12 -password pass:openssl -in SslEccRoot.pfx -out SslEccRoot.pem2 -nokeys
openssl x509 -in SslEccRoot.pem2 -out SslEccRoot.pem3
openssl pkcs12 -password pass:openssl -in SslEccRoot.pfx -out SslEccRoot.key2 -nodes -nocerts
openssl ec -in SslEccRoot.key2 -out SslEccRoot.key
dir SslEccRoot.*

certreq -f -new -q -cert "SslEccRoot" SslEccCA2.inf SslEccCA2.csr
certutil -f -store -user My SslEccCA2 SslEccCA2.cer
openssl x509 -inform der -in SslEccCA2.cer -out SslEccCA2.pem
certutil -f -exportPFX -p "openssl" -user My SslEccCA2 SslEccCA2.pfx
openssl pkcs12 -password pass:openssl -in SslEccCA2.pfx -out SslEccCA2.pem2 -nokeys
openssl x509 -in SslEccCA2.pem2 -out SslEccCA2.pem3
openssl pkcs12 -password pass:openssl -in SslEccCA2.pfx -out SslEccCA2.key2 -nodes -nocerts
openssl ec -in SslEccCA2.key2 -out SslEccCA2.key
dir SslEccCA2.*

certreq -f -new -q -cert "SslEccCA2" SslEccServer2.inf SslEccServer2.csr
certutil -f -store -user My SslEccServer2 SslEccServer2.cer
openssl x509 -inform der -in SslEccServer2.cer -out SslEccServer2.pem
certutil -f -exportPFX -p "openssl" -user My SslEccServer2 SslEccServer2.pfx
openssl pkcs12 -password pass:openssl -in SslEccServer2.pfx -out SslEccServer2.pem2 -nokeys
openssl x509 -in SslEccServer2.pem2 -out SslEccServer2.pem3
openssl pkcs12 -password pass:openssl -in SslEccServer2.pfx -out SslEccServer2.key2 -nodes -nocerts
openssl ec -in SslEccServer2.key2 -out SslEccServer2.key
cmd /c copy SslEccServer2.pem+SslEccCA2.pem+SslEccRoot.pem SslEccServer2.chain
dir SslEccServer2.*

certreq -f -new -q -cert "SslEccCA2" SslEccClient2.inf SslEccClient2.csr
certutil -f -store -user My SslEccClient2 SslEccClient2.cer
openssl x509 -inform der -in SslEccClient2.cer -out SslEccClient2.pem
certutil -f -exportPFX -p "openssl" -user My SslEccClient2 SslEccClient2.pfx
openssl pkcs12 -password pass:openssl -in SslEccClient2.pfx -out SslEccClient2.pem2 -nokeys
openssl x509 -in SslEccClient2.pem2 -out SslEccClient2.pem3
openssl pkcs12 -password pass:openssl -in SslEccClient2.pfx -out SslEccClient2.key2 -nodes -nocerts
openssl ec -in SslEccClient2.key2 -out SslEccClient2.key
cmd /c copy SslEccClient2.pem+SslEccCA2.pem+SslEccRoot.pem SslEccClient2.chain
dir SslEccClient2.*

certreq -f -new -q -cert "SslEccCA2" SslEccServerClient.inf SslEccServerClient.csr
certutil -f -store -user My SslEccServerClient SslEccServerClient.cer
openssl x509 -inform der -in SslEccServerClient.cer -out SslEccServerClient.pem
certutil -f -exportPFX -p "openssl" -user My SslEccServerClient SslEccServerClient.pfx
openssl pkcs12 -password pass:openssl -in SslEccServerClient.pfx -out SslEccServerClient.pem2 -nokeys
openssl x509 -in SslEccServerClient.pem2 -out SslEccServerClient.pem3
openssl pkcs12 -password pass:openssl -in SslEccServerClient.pfx -out SslEccServerClient.key2 -nodes -nocerts
openssl ec -in SslEccServerClient.key2 -out SslEccServerClient.key
cmd /c copy SslEccServerClient.pem+SslEccCA2.pem+SslEccRoot.pem SslEccServerClient.chain
dir SslEccServerClient.*
