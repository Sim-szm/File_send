#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

int main()
{
DIR *db;
char filename[256],path[1024];
struct dirent *p;
FILE *file;

time_t curdate,towwork;
struct tm *tdate;
int year=0,month=0,day=0;
file=fopen("./config","r");
if(!file){
printf("config not exist!\n");
return -1;
}
memset(path,0,sizeof(path));
fgets(path,sizeof(path),file);
if(path[strlen(path)-1]=='\n')path[strlen(path)-1]='\0';
db=opendir(path);
if(!db){
        printf("open %s error!\n",path);
        return -1;
}
        while(p=readdir(db))
        {
                if(strcmp(p->d_name,".")==0||strcmp(p->d_name,"..")==0)
                continue;
                time(&curdate);
                tdate = localtime (&curdate);
                year=day=month=0;
                sscanf(p->d_name,"%04d%02d%02d",&year,&month,&day);
                if(year==0||month==0||day==0)continue;
                tdate->tm_mday = day;
                tdate->tm_mon = month-1;
                tdate->tm_year =year-1900;
                towwork=mktime(tdate);
                if(towwork<(curdate-2*7*24*3600))printf("%s\n",p->d_name);
        }
closedir(db);
return 0;
}


