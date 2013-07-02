gcc -o server-ssl server-ssl.c -g -Wall -lssl -lcrypto -ldl
echo "server-ssl complied !\n"
gcc -o client-ssl client-ssl.c -g -Wall -lssl -lcrypto -ldl
echo "client-ssl complied !\n"
