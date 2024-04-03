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
cat ./credentials

toor@laptop:/home/user/projects/microvault# ./microvault --path ./credentials --provider ./generator.sh --consumer ./consumer.sh 
2024-04-02T12:27:33.728038921+02:00 Initializing micro vault...

-> Vaulted file = /home/user/projects/microvault/credentials
-> Provider file = /home/user/projects/microvault/generator.sh
-> Consumer file = /home/user/projects/microvault/consumer.sh

2024-04-02T12:27:33.72876466+02:00 -> Running provider /home/user/projects/microvault/generator.sh by main program (pid=25042)
2024-04-02T12:27:33.730425859+02:00 -> Started /home/user/projects/microvault/generator.sh, pid=25047
2024-04-02T12:27:33.731631468+02:00 -> Starting event pump
2024-04-02T12:27:33.735981654+02:00 Provider was executed by micro vault
2024-04-02T12:27:33.736136716+02:00 EVENT 65536 -> PID:25047 path:/home/user/projects/microvault/generator.sh  -> ACCESS_GRANTED_PROVIDER_
!!!! This is generator !!!!
2024-04-02T12:27:33.741818506+02:00 Vaulted file being accessed
2024-04-02T12:27:33.742335918+02:00 Process allowed to read vault: /usr/bin/dash, pid=25047
2024-04-02T12:27:33.742426098+02:00 EVENT 65536 -> PID:25047 path:/home/user/projects/microvault/credentials  -> ACCESS_GRANTED_VAULT_
2024-04-02T12:27:42.457898265+02:00 Vaulted file being accessed
2024-04-02T12:27:42.458995707+02:00 Process not allowed to read vault: /usr/bin/cat, pid=25152, parent=/usr/bin/bash
2024-04-02T12:27:42.459115791+02:00 EVENT 65536 -> PID:25152 path:/home/user/projects/microvault/credentials  -> ACCESS_DENIED_VAULT_
2024-04-02T12:27:44.655671299+02:00 Consumer exe being executed as pid=25190
2024-04-02T12:27:44.655725913+02:00 EVENT 65536 -> PID:25190 path:/home/user/projects/microvault/consumer.sh  -> ACCESS_GRANTED_CONSUMER
error: internal routine/ fanotify: event error, read : text file busy
2024-04-02T12:27:44.658474991+02:00 EVENT 65536 -> PID:25190 path:/home/user/projects/microvault/consumer.sh  -> ACCESS_GRANTED_CONSUMER
2024-04-02T12:27:45.664465502+02:00 Vaulted file being accessed
2024-04-02T12:27:45.66499988+02:00 Process allowed to read vault: /usr/bin/cat, pid=25192
2024-04-02T12:27:45.665100883+02:00 EVENT 65536 -> PID:25192 path:/home/user/projects/microvault/credentials  -> ACCESS_GRANTED_VAULT_

toor@localhost:/home/user/projects/microvault# ./consumer.sh 
!!! This is consumer !!!
Tue Apr  2 12:30:58 CEST 2024

toor@laptop:/home/user/projects/microvault# cat ./credentials 
cat: ./credentials: Operation not permitted
toor@laptop:/home/user/projects/microvault#
```
### Usecase: Samba share mounted with protected credentials
![mount without microvault](freenas_access_001.png)

![microvault systemd service](freenas_access_002.png)

![operation not permitted](freenas_access_003.png)
