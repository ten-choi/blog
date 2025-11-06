Listen 443

SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLProxyCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLHonorCipherOrder on
SSLProtocol all -SSLv3
SSLProxyProtocol all -SSLv3
SSLPassPhraseDialog builtin
SSLSessionCache "shmcb:/usr/local/apache/logs/ssl_scache(512000)"
SSLSessionCacheTimeout 300

<VirtualHost _:443>
DocumentRoot "/usr/local/apache/htdocs"
ServerName alpha.hange.jp
ServerAlias alpha-_.hange.jp

# DocumentRoot /home/www/projects/your-test/html/hangame-alice/web

# <Location />

# Require ip 183.91.2.211

# </Location>

    <Directory "/home/www/projects/hange-alice/hange-alice">
        Options -Indexes +FollowSymLinks +Multiviews
        AllowOverride None
        Require all granted
    </Directory>

     DirectoryIndex index.html index.htm

     SSLEngine on

     SSLCertificateFile /home/www/hange-ssl/hange-jp/hange.jp.crt
     SSLCertificateKeyFile /home/www/hange-ssl/hange-jp/hange.jp.key

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"


    RewriteCond %{REQUEST_URI} ^(.*)\.nhn$ [NC]
    RewriteRule ^(.*)\.nhn$ $1 [R=301,L]

    # alpha-XXX → /XXX/index
    RewriteEngine On
    RewriteCond %{HTTP_HOST} ^alpha-([^.]+)\.hange\.jp$ [NC]
    RewriteRule ^/$ ajp://127.0.0.1:6008/%1/index [P,L]

    # alpha-XXX → /XXX/요청경로
    RewriteCond %{HTTP_HOST} ^alpha-([^.]+)\.hange\.jp$ [NC]
    RewriteCond %{REQUEST_URI} !^/$
    RewriteRule ^/(.*)$ ajp://127.0.0.1:6008/%1/$1 [P,L]

    ErrorLog "/usr/local/apache/logs/error_log"
    TransferLog "/usr/local/apache/logs/access_log"
    CustomLog "/usr/local/apache/logs/ssl_request_log" "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

</VirtualHost>
