# microvault
Fanotify-based program allowing or denying access to file with credentials

## demo
```
toor@laptop:/home/user/projects/microvault# cat generator.sh 
#!/bin/sh
echo "!!!! This is generator !!!!"
echo `date`  > ./credentials

toor@laptop:/home/user/projects/microvault# cat consumer.sh 
#!/bin/sh
echo "!!! This is consumer !!!"
sleep 1
cat ./credential

toor@laptop# ./microvault --path ./credentials --provider ./generator.sh --consumer ./consumer.sh 
Initializing micro vault...

-> Vault file = /home/user/projects/microvault/credentials
-> provider file = /home/user/projects/microvault/generator.sh
-> Consumer file = /home/user/projects/microvault/consumer.sh

-> Running provider /home/user/projects/microvault/generator.sh by 11956
-> Started /home/user/projects/microvault/generator.sh, 11961
-> Starting event pump
provider was executed by micro vault
!!!! This is generator !!!!
2024-04-02T09:50:27.321091973+02:00 EVENT 65536 -> PID:11961 path:/home/user/projects/microvault/generator.sh  -> ACCESS_GRANTED_CONSUMER_
Credentials file being accesses
Process allowed to read vault: /usr/bin/dash, 11961
2024-04-02T09:50:27.322765236+02:00 EVENT 65536 -> PID:11961 path:/home/user/projects/microvault/credentials  -> ACCESS_GRANTED_VAULT_
Consumer exe being executed as pid=12258
2024-04-02T09:51:27.099772614+02:00 EVENT 65536 -> PID:12258 path:/home/user/projects/microvault/consumer.sh  -> ACCESS_GRANTED_CONSUMER
error: Internal routine/ fanotify: event error, read : text file busy
2024-04-02T09:51:27.106310726+02:00 EVENT 65536 -> PID:12258 path:/home/user/projects/microvault/consumer.sh  -> ACCESS_GRANTED_CONSUMER
Credentials file being accesses
Process allowed to read vault: /usr/bin/cat, 12263
2024-04-02T09:51:28.111662566+02:00 EVENT 65536 -> PID:12263 path:/home/user/projects/microvault/credentials  -> ACCESS_GRANTED_VAULT_
Credentials file being accesses
Process not allowed to read vault: /usr/bin/cat, 12378, parent=/usr/bin/bash
2024-04-02T09:51:41.521114644+02:00 EVENT 65536 -> PID:12378 path:/home/user/projects/microvault/credentials  -> ACCESS_DENIED_VAULT_
...

toor@laptop:/home/user/projects/microvault# ./consumer.sh 
!!! This is consumer !!!
wto, 2 kwi 2024, 09:50:27 CEST
root@user-ux360cak:/home/user/projects/microvault# cat ./credentials 
cat: ./credentials: Operation not permitted
toor@laptop:/home/user/projects/microvault#
``` 



