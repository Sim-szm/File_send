/*
 * =====================================================================================
 *       Filename:  server-ssl.c
 *    Description:  
 *        Created:  2012年12月5日 19时37分55秒
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/ipc.h>

#include "log_recond.h"

#define MAXBUF 1024
#define myport 8080
#define BACK_LOG 3
#define MAXPATH 32
#define SCAN_PATH "/home/szm/music"

int count=0;
double filesize;            //文件总大小
//char cookie_buf[50];
struct list
{
    char pathname[1024];
    char filename[512];
    struct list *next;
};

LOG_TYPE *recond_log;

struct list *head,*p1,*p2;

void scan_dir(char *dir)          //定义目录扫描函数
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuff;
    if(!(dp=opendir(dir)))
    {
        perror("scan_dir :can't open dir !\n");
        return;
    }

    chdir(dir);             //切换到当前目录中去
    while((entry=readdir(dp))!=NULL)
    {
        lstat(entry->d_name,&statbuff); //获取下一级成员属性
        if(S_IFDIR&statbuff.st_mode)   
        {
            if(strcmp(".",entry->d_name)==0||strcmp("..",entry->d_name)==0)
            continue;
            scan_dir(entry->d_name);
       
        }

        else
             {
                    char path_buff[MAXPATH];
                    getcwd(path_buff, MAXPATH);

                    p1= malloc(sizeof(struct list));

                    strcpy(p1->pathname,path_buff);
                    strcpy(p1->filename,entry->d_name);
                   
                    p1->next=NULL;
                    count++;
                   
                    if(count==1)
                        head=p2=p1;
                    else
                    {   
                        p2->next=p1;
                        p2=p1;
                       
                    }
                                 
                    int tem;
                    tem = statbuff.st_size;
                    filesize+=tem;
                             
            }
    }

    chdir("..");                //回到上一级目录
    closedir(dp);

}


int print(struct list *head)
{
   
    struct list *temp;
    temp=head;

    if(head!=NULL)
    do {
        printf("%s %s\n",temp->pathname,temp->filename);
           
        temp=temp->next;   
    }while(temp!=NULL);

    return 0;
}


void send_file(struct list *temp,SSL *ssl,struct stat statbuff,char *send_md5_value)
{
         char fileinfo[512];                 //定义文件信息，包括文件路径和文件名 
         memset(fileinfo,0,512);

         char filename[512];
         memset(filename,0,512);
         char check[7]="SUCCESS";
         char c[2]={'/'};
          int filesize=0;
          //int sendfsize;
         strcat(temp->pathname,c);
         strcat(temp->pathname,temp->filename);
           
        //  printf("temp->pathname=%s\n",temp->pathname);
           
         strcpy(fileinfo,temp->pathname);
         strcpy(filename,temp->filename);
           
         printf("fileinfo=%s\n",fileinfo);
          //  printf("filename=%s\n",filename);
                              
          int sendbytes=0;
         sendbytes=SSL_write(ssl,&filename,512);
         if(sendbytes<=0)
         {
           printf("error %s",strerror(errno));
           Write_Log(ERROR_MODE_TYPE,strerror(errno),recond_log);
         }
         else{
            printf("sendbytes=%d\n",sendbytes);
         }

        sendbytes=SSL_write(ssl,send_md5_value,512);

        lstat(fileinfo,&statbuff);
        filesize=statbuff.st_size;
        printf("filesize =%d\n",filesize);

        SSL_write(ssl,&filesize,4);  
        char buff[MAXBUF];
        memset(buff,'\0',MAXBUF);
                       
      FILE * fp = fopen(fileinfo,"r");
    
       if(NULL == fp )
       {
         strcat(fileinfo," <file not found !>");
          puts("**************************************");
          Write_Log(ERROR_MODE_TYPE,fileinfo,recond_log);

          puts("**************************************");
       }
   
        else
       {
         int file_block_length = 0;
       
         while( (file_block_length = fread(buff,sizeof(char),MAXBUF,fp))>0)               
         {        
           
            if(SSL_write(ssl,buff,file_block_length)<0)
             {

                 Write_Log(ERROR_MODE_TYPE,"send file failed !",recond_log);

                 break;
             }
       
            memset(buff,'\0',MAXBUF);
         }
   
         fclose(fp);           
        }

       SSL_read(ssl,check,sizeof(check)); 
       memset(fileinfo,0,512);
       memset(filename,0,512);

      if(strcmp(check,"SUCCESS")==0)
       {
		   printf("file send success !\n");
       Write_Log(SYSTEM_MODE_TYPE,"success",recond_log);

	   } 
      else
          {
            printf("file send failed !");
           Write_Log(ERROR_MODE_TYPE,"file send failed !",recond_log);

          } 
}

struct list * find_file(struct list *p,char *send_file_type)
{
    char *q;
    char last[10]={'\0'};
    int i=0;
   struct list *retu,*p1,*back;

   p1=retu=(struct list*)malloc(sizeof(struct list));
   retu->next=NULL;

   while(NULL!=p)
   {
      i=0;
      q=strchr(p->filename,'.');
      while(q[i]!='\0'){
    	last[i]=q[i];
         i++;
     }
     if(strcmp(last,send_file_type)==0)
     {
       back=(struct list *)malloc(sizeof(struct list));
       strcpy(back->filename,p->filename);
       strcpy(back->pathname,p->pathname);
       p1->next=back;
       p1=back;
     }
     p=p->next;
   } 

    p1->next=NULL;
   return retu;
}
struct list *find_single_file(struct list *p,char *send_file_name){

	while(NULL!=p){
		if(strcmp(p->filename,send_file_name)==0){
			return p;
		}
		p=p->next;
	}
	return NULL;
}
int find_num(struct list *find)
{
    int num=0;
    while(NULL!=find)
    {
       num++;
       find=find->next;
    }
   return num;
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
   {
	   printf ("%s can't be opened\n", filename);
     Write_Log(ERROR_MODE_TYPE,"*get md5 value error (open file)!*",recond_log);

       return 0;
   }
   else {
        Write_Log(SYSTEM_MODE_TYPE,"*md5 jiaoyan start*",recond_log);

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
void file_get()
{
  char *dir=(char *)malloc(sizeof(char)*MAXPATH);
  puts("**************************************");
    fflush(stdin);
    strcpy(dir,SCAN_PATH);

    puts("**************************************");
    puts("   正在扫描目录中......   "); 
    Write_Log(SYSTEM_MODE_TYPE,"正在扫描目录中....",recond_log);
    scan_dir(dir);
    puts("**************************************");
    printf("   列表输出如下：\n");
    print(head);       
    puts("    扫描结束   ");
    puts("**************************************");
    printf("    共计%d个文件\n",count);
    printf("    总大小为%3.2gMB\n",filesize/1024/1024);
    puts("**************************************");

}
void file_process(char *argv1,char *argv2)
{
	int server_sockfd,message_sockfd;
	socklen_t len;
	int server_len;
        int num;

	struct sockaddr_in server_sockaddr,client_sockaddr;

	SSL_CTX *ctx;
	SSL *ssl;
        pid_t pid;
	//char *dir=(char *)malloc(sizeof(char)*MAXPATH);
	char *send_file_type=(char *)malloc(sizeof(char)*10);

  char path[80];
  memset(path,'\0',80);
  strcpy(path,"./love_log");
  mkdir(path,S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
  //LOG_TYPE *recond_log;
  recond_log=(LOG_TYPE *)malloc(sizeof(LOG_TYPE));
  
  if(Create_Log(ERROR_MODE_TYPE,"error_log.txt",recond_log)==-1){
    perror("create error_log file error");
     exit(1);
  }
  if(Create_Log(SYSTEM_MODE_TYPE,"system_log.txt",recond_log)==-1){
    perror("create system_log file error");
    exit(1);
  }
  Write_Log(ERROR_MODE_TYPE,"error_log start  ",recond_log);
  Write_Log(SYSTEM_MODE_TYPE,"system_log start  ",recond_log);


	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx=SSL_CTX_new(SSLv23_server_method());

	if(ctx==NULL){

		ERR_print_errors_fp(stdout);
    Write_Log(ERROR_MODE_TYPE,"SSL_CTX_new error !",recond_log);

		exit(1);
	}
	if(SSL_CTX_use_certificate_file(ctx,argv1,SSL_FILETYPE_PEM)<=0){

		ERR_print_errors_fp(stdout);
    Write_Log(ERROR_MODE_TYPE,"SSL_CTX_use_certificate_file error!",recond_log);

		exit(1);
	}
	if(SSL_CTX_use_PrivateKey_file(ctx,argv2,SSL_FILETYPE_PEM)<=0){

		ERR_print_errors_fp(stdout);
    Write_Log(ERROR_MODE_TYPE,"SSL_CTX_use_PrivateKey_file error !",recond_log);
		exit(1);
	}
	if(!SSL_CTX_check_private_key(ctx)){

		ERR_print_errors_fp(stdout);
    Write_Log(ERROR_MODE_TYPE,"SSL_CTX_check_private_key error !",recond_log);

		exit(1);
	}
	if((server_sockfd=socket(AF_INET,SOCK_STREAM,0))==-1){

		Write_Log(ERROR_MODE_TYPE,"socket init error !",recond_log);
		exit(1);
	}

	bzero(&(client_sockaddr),0);
  bzero(&(server_sockaddr),0);

	server_sockaddr.sin_family=AF_INET;
	server_sockaddr.sin_port=htons(myport);
	server_sockaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	server_len=sizeof(server_sockaddr);

	int opt=1;
	setsockopt(server_sockfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

	if(bind(server_sockfd,(struct sockaddr*)&server_sockaddr,server_len)==-1){

    Write_Log(ERROR_MODE_TYPE,"bind error !",recond_log);
		exit(1);
	}
	if(listen(server_sockfd,BACK_LOG)==-1){

		Write_Log(ERROR_MODE_TYPE,"listen error !",recond_log);
		exit(1);
	}


	len=sizeof(struct sockaddr);
  file_get();

  Write_Log(SYSTEM_MODE_TYPE,"listening !",recond_log);
	while(1){

		if((message_sockfd=accept(server_sockfd,(struct sockaddr*)&client_sockaddr,&len))==-1){

      Write_Log(ERROR_MODE_TYPE,"accept error ",recond_log);
			exit(errno);
		}
		else{
			puts("**************************************");

                        printf("    %s连接到服务器\n",inet_ntoa(client_sockaddr.sin_addr));
                        Write_Log(SYSTEM_MODE_TYPE,inet_ntoa(client_sockaddr.sin_addr),recond_log);
                        Write_Log(SYSTEM_MODE_TYPE," :connected us ! ",recond_log);
                        puts("**************************************");
                        printf("    准备发送文件.......\n");
                        puts("**************************************");
		}

        pid=fork();
           if(pid==0)
             {
  		ssl=SSL_new(ctx);
		SSL_set_fd(ssl,message_sockfd);
                  //发送文件数目
                int countbyte;
          //char *send_file_name=(char *)malloc(sizeof(char)*50);
          //memset(send_file_name,'\0',50);
          //countbyte=send(message_sockfd,&count,4,0);
         // printf("countbyte=%d\n",countbyte);

         /*char fileinfo[100];                 //定义文件信息，包括文件路径和文件名
         memset(fileinfo,0,100);
         char filename[50];
         memset(filename,0,50);*/
   
                 struct stat statbuff;
                 struct list *p;
				        char send_md5_value[512];
				        memset(send_md5_value,'\0',512);
                char *send_single_file_name=(char *)malloc(sizeof(char)*512);
        		 char *od;
		         int i=0;
        		 char c[2]={'/'};
                 int choose;

                fflush(stdin);
                printf("\n可以发送以下几种文件类型：(若没有需要的文件类型请选择 6（单个文件发送）)\n");
                printf("*************\n0 : mp3类\n1 : mp4类\n2 : wmv类\n3 : avi类\n4 : jpg类\n5 ： 全部发送\n6 : single file（need to input file_name） \n7 : 自己输入文件后缀名（like < .doc >{注意加‘.’}）\n****************\n");
   loop:        printf("选择发送文件的类型 ：");
                scanf("%d",&choose);
				getchar();

		if(SSL_accept(ssl)==-1){
		Write_Log(ERROR_MODE_TYPE,"SSL_accept error !",recond_log);
			close(message_sockfd);
			break;
		}
                switch(choose)
                {
			 case 0:
                                if(head!=NULL)
				               {
                                    strcpy(send_file_type,".mp3");
                                    p=find_file(head,send_file_type);
                                    p=p->next;
                                    num=find_num(p);
                                
                                    countbyte=SSL_write(ssl,&num,sizeof(num));
                                    printf("countbyte=%d\n",countbyte); 

				                   do{   
									   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }
                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next;
                                         num--;
										                 if(num==0) 
                                      printf("send over \n");
										 Write_Log(SYSTEM_MODE_TYPE,"file send over !",recond_log);

                                   }while(p!=NULL);
                               }
                                 break;

			 case 1:
                                 if(head!=NULL)
				                 {
                                memset(send_md5_value,'\0',512);
                                    strcpy(send_file_type,".mp4");
                                    p=find_file(head,send_file_type);
                                    p=p->next;
                                    num=find_num(p);
                                
                                    countbyte=SSL_write(ssl,&num,sizeof(num));
                                    printf("countbyte=%d\n",countbyte);  

				                   do{ 
                                  		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }                                     
                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next;
                                       num--;
									   if(num==0) 
                      printf("file send over\n");
									Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                   }while(p!=NULL);
                                 }
                                 break;
                         
			 case 2:
                                 if(head!=NULL)
				                 {
                                   memset(send_md5_value,'\0',512);
                                    strcpy(send_file_type,".wmv");
                                    p=find_file(head,send_file_type);
                                    p=p->next;
                                    num=find_num(p);
                                
                                    countbyte=SSL_write(ssl,&num,sizeof(num));
                                    printf("countbyte=%d\n",countbyte);  

				                   do{   
                             		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }                                   

                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next;
                                     num--;
									 if(num==0) 
                     printf("file send over\n");
									 Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);

                                   }while(p!=NULL);
                                 }
                                 break;
			 case 3:
                                 if(head!=NULL)
				                 {
                                    memset(send_md5_value,'\0',512);
                                    strcpy(send_file_type,".avi");
                                    p=find_file(head,send_file_type);
                                    p=p->next;
                                    num=find_num(p);
                                
                                    countbyte=SSL_write(ssl,&num,sizeof(num));
                                    printf("countbyte=%d\n",countbyte); 

				                   do{ 
                                  		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }                                     
                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next;
                                       num--;
									   if(num==0) 
                       printf("file send over\n");
										Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                   }while(p!=NULL);
                                 }
                                 break;
			 case 4:
                                 if(head!=NULL)
				                {
                                     memset(send_md5_value,'\0',512);
                                    strcpy(send_file_type,".jpg");
                                    p=find_file(head,send_file_type);
                                    p=p->next;
                                    num=find_num(p);
                                
                                    countbyte=SSL_write(ssl,&num,sizeof(num));
                                    printf("countbyte=%d\n",countbyte);  

				                   do{  
                               		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }                                    
                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next;
                                       num--;
									   if(num==0) 
                       printf("file send over\n");
										Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                   }while(p!=NULL);
                                 }
                                 break;
			 case 5:
                               if(head!=NULL)
							   {
                                  memset(send_md5_value,'\0',512);
                                   count=find_num(head);
                                   countbyte=SSL_write(ssl,&count,4);
                                    printf("countbyte=%d\n",countbyte);
                                    p=head;
                                     do{
                                    		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }
                                       send_file(p,ssl,statbuff,send_md5_value);
                                       p=p->next; 
                                      num--;
									  if(num==0) 
                       printf("file send over\n");
										Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                     }while(p!=NULL);
                               }
                                break;
			 case 6:    if(head!=NULL)
				      {       
										 memset(send_md5_value,'\0',100);
                                         memset(send_single_file_name,'\0',512); 

                      re_file:           printf("input single file name :");
		                                 fflush(stdin);
                                         gets(send_single_file_name);
					                     p=find_single_file(head,send_single_file_name);

										 strcpy(send_single_file_name,p->pathname);
										 strcat(send_single_file_name,c);
										 strcat(send_single_file_name,p->filename);

										 od=Get_Md5_Value(send_single_file_name);
										 while(od[i]!='\0'){
											 send_md5_value[i]=od[i];
											 i++;
										 }
										// printf("\n**************************\n%s\n*****************************\n",send_md5_value);
                                         if(p==NULL) 
                                          { 
                                             num=0;
                                             printf("file not found !  input again\n");
                                             Write_Log(ERROR_MODE_TYPE," *file not found!* ",recond_log);
                                             goto re_file;
                                          }
					                     else 
                                         { 
                                               num=1;
					                           countbyte=SSL_write(ssl,&num,sizeof(num));
                       					       printf("countbyte=%d\n",countbyte);
					                           send_file(p,ssl,statbuff,send_md5_value);
                                               num--;
											   if(num==0) 
                           printf("file send over\n");

												Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                         }
					 }
				 break;
			 case 7:
				    if(head !=NULL){
					      char file_type[10];
					      memset(file_type,'\0',10);
			re_type:	  printf("input single file type :");
		                         fflush(stdin);

					      gets(file_type);
					      strcpy(send_file_type,file_type);

                                         p=find_file(head,send_file_type);
                                         p=p->next;
                                         if(p==NULL) 
                                          { 
                                             num=0;
                                             printf("file type not found !  input again\n");
                                             Write_Log(ERROR_MODE_TYPE," *file not found!* ",recond_log);
                                             goto re_type;
                                          }
                                         else
                                         {  num=find_num(p);                                
                                            countbyte=SSL_write(ssl,&num,sizeof(num));
                                            printf("countbyte=%d\n",countbyte);                             
				                   do{  
                                            		   i=0;
                                      memset(send_md5_value,'\0',512);  
									  memset(send_single_file_name,'\0',512);

									  strcpy(send_single_file_name,p->pathname);
									  strcat(send_single_file_name,c);
									  strcat(send_single_file_name,p->filename);

									  od=Get_Md5_Value(send_single_file_name);
									  while(od[i]!='\0'){
										  send_md5_value[i]=od[i];
										  i++;
									  }                                    
                                            send_file(p,ssl,statbuff,send_md5_value);
                                            p=p->next;
                                           num--;
										   if(num==0) 
                         printf("file send over\n");

											Write_Log(SYSTEM_MODE_TYPE," *file send over !* ",recond_log);
                                   }while(p!=NULL);
                                         }
				 }
				 break ;

	          default :
		                     Write_Log(ERROR_MODE_TYPE,"choose value error !",recond_log);
                              goto loop;
                 }
        
               }
               if(pid>0)
               {
                  close(message_sockfd);
               }
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(server_sockfd);
	SSL_CTX_free(ctx);
}

int main(int argc,char *argv[])
{
  file_process(argv[1],argv[2]);
  return 0;
}

