https://hub.docker.com/r/rsyslog/rsyslog_dev_base_ubuntu/tags

exec into container and build

sudo setfacl -m u:1000:rwx -R .

update the rsyslog.conf with your machine IP addr to route the omhttp message from the container to your local machine.


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