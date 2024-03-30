# microvault
Fanotify-based program allowing or denying access to file with credentials

## demo
toor@laptop:/home/user/projects/microvault# cat generator.sh 
#!/bin/sh
echo "!!!! This is generator !!!!"
echo `date`  > ./credentials

toor@laptop:/home/user/projects/microvault# cat consumer.sh 
#!/bin/sh
echo "!!! This is consumer !!!"
sleep 1
cat ./credentialsroot

toor@laptop:/home/user/projects/microvault# touch ./credentials; ./microvault --path ./credentials --provider ./generator.sh --consumer ./consumer.sh


