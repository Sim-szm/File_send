/*
 * =====================================================================================
 *       Filename:  client-ssl.c
 *    Description:  
 *        Created:  2012年11月27日 20时58分55秒
 *       Revision:  none
 *       Compiler:  clang
 *         Author:  szm 
 *         Email :  xianszm007@gmail.com
 *        Company : class 7 of computer science 
 * =====================================================================================
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/md5.h>
#define MAXBUF 1024
void ShowCerts(SSL *ssl){
	X509 *cert;
	char *line;
	cert=SSL_get_peer_certificate(ssl);
	if(cert!=NULL){
		printf("number cert info :\n");
		line=X509_NAME_oneline(X509_get_subject_name(cert),0,0);
		printf("cert : %s\n",line);
		//free(line);
		line=X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
		printf("giver : %s\n",line);
		free(line);
		X509_free(cert);
	}else{
		printf("no cert !\n");
	}
}
char* Get_Md5_Value(char *filename)
{
   static char output[33]={""};
   FILE *file;
   MD5_CTX context;
   int len;
   unsigned  char buffer[1024], digest[16];
   int i;
   char output1[32];
   if ((file = fopen (filename, "rb")) == NULL)
   { printf ("%s can't be opened\n", filename);
     return 0;
   }
   else {
       MD5_Init(&context);
     while ((len = fread (buffer, 1, 1024, file))>0)
       MD5_Update(&context,(unsigned char*)buffer, len);
       MD5_Final(digest, &context);
       fclose(file);
       for (i = 0; i < 16; i++)
       {  
          sprintf(&(output1[2*i]),"%02x",(unsigned char)digest[i]);
          sprintf(&(output1[2*i+1]),"%02x",(unsigned char)(digest[i]<<4));
       }
       for(i=0;i<32;i++)
          output[i]=output1[i];
       return output;
    }

}
int main( int argc, char *argv[] ){
	int sockfd;
	struct sockaddr_in serv_addr;
        char filename[512];
        memset(filename,0,512);
        int filesize;
        unsigned char databuf[1000];
	SSL_CTX *ctx;
	SSL *ssl;
        int i;
        int lastsize=0;
        char md5_value[512];
	char md5_value_for_check[512];
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx=SSL_CTX_new(SSLv23_client_method());
	if(ctx==NULL){
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0){
		perror("socket error");
		exit(1);
	}
	puts("socket created ");
	bzero(&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(8080);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	puts("address created !");
	if(connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr))!=0){
		perror("connect error!");
		exit(1);
	}
        int count=0;
	ssl=SSL_new(ctx);
	SSL_set_fd(ssl,sockfd);
	if(SSL_connect(ssl)==-1){
		ERR_print_errors_fp(stderr);
	}else{
		printf("connected with %s \n",SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
        SSL_read(ssl,&count,sizeof(count));
        printf("文件数目=%d\n",count);
        if(count==0) goto finish;
     while(count!=0)
     { 
		  memset(md5_value,'\0',512);
		  memset(md5_value_for_check,'\0',512);
        i=SSL_read(ssl,filename,sizeof(filename));         //接收文件名
    //  printf("recv %d bytes\n",i);
        printf("file name=%s\n",filename);                 
		i=SSL_read(ssl,md5_value,sizeof(md5_value));
		printf("file md5_value :%s\n",md5_value);
        i=SSL_read(ssl,&filesize,sizeof(filesize));        //接收文件大小
   //   printf("recv %d bytes\n",i);
       // printf("filesize=%d\n",filesize);
        lastsize=filesize;                            //文件大小赋给变量
       
        //接收文件内容
        FILE *fp = fopen(filename,"w");
		char *od;
     
        if(NULL == fp )
        {
            printf("File: Can Not Open To Write\n");
            exit(1);
        }
       
        i=0;
        while(lastsize!=0)
        {
            //printf("lastsize=%d\n",lastsize);
            if(lastsize>sizeof(databuf))
            {
                 i=SSL_read(ssl,databuf,sizeof(databuf));
                // printf("接收字节i=%d\n",i);
                if(i<0){
	           printf("failed to recv message | error :%s\n",strerror(errno));
	             goto finish;
	        }
                 int write_length = fwrite(databuf,sizeof(char),i,fp);
                 if (write_length<i)
                     {
                         printf("File:Write Failed\n");send(sockfd,"FAILED",sizeof("FAILED"),0);
                           break;
                     }
               
            //  if(lastsize<5000) printf("recv %d bytes\n",i);
            }
            else
            {
                i=SSL_read(ssl,databuf,lastsize);
               // printf("接收字节i=%d\n",i);
               
               
               int write_length = fwrite(databuf,sizeof(char),i,fp);
                if (write_length<i)
                     {
                         printf("File:Write Failed\n");send(sockfd,"FAILED",sizeof("FAILED"),0);
                           break;
                     }
               
           //       printf("*******recv %d bytes\n",i);
            }
           
            lastsize=lastsize-i;
         }
       
         fclose(fp);
	   i=0;
	   od=Get_Md5_Value(filename);
	   while(od[i]!='\0'){
		   md5_value_for_check[i]=od[i];
		   i++;
	   }
	   if(strcmp(md5_value_for_check,md5_value)==0){
         SSL_write(ssl,"SUCCESS",sizeof("SUCCESS"));
		 printf("the file get over !\n");
		 count--;
	   }
	   else{
		 SSL_write(ssl,"FAILED resend!",sizeof("FAILED resend!"));
		 printf("not yet !\n");
	   }
       printf("\nfile number is %d\n",count);
	   if(count==0){
		   printf("\nfile taken over !\n");
	   }
      }
finish:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}


