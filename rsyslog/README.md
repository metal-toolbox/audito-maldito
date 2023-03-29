https://hub.docker.com/r/rsyslog/rsyslog_dev_base_ubuntu/tags

exec into container and build

sudo setfacl -m u:1000:rwx -R .


```
./autogen.sh
./configure --enable-omhttp --enable-shared
make
make install
find / -type f -name omhttp.so
```


```
go build . && make image && make rsyslog
```