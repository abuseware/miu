/* Application: MIU - MAC In Userspace v 2.0
 * Author: thc_flow
 *
 * Created on October 21, 2011, 9:56 AM
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 Unported License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/3.0/ or send a letter to
 * Creative Commons, 444 Castro Street, Suite 900, Mountain View, California, 94041, USA.
 */


/* HEEEEY, LOOK HERE! */
#ifndef CFGPATH
  #define CFGPATH "/etc/miu.ini"
#endif
/* OK, NOW GTFO */

/* oldfags */
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
/* errno */
#include <errno.h>
/* bind */
#include <sys/socket.h>
#include <netinet/in.h>
/* int*_t */
#include <linux/types.h>
/* groups */
#include <sys/types.h>
#include <grp.h>
/* config */
#include <iniparser.h>
#include <stdio.h>
#include <regex.h>
#include <string.h>
/* dlsym */
#define __USE_GNU
  #include <dlfcn.h>
#undef __USE_GNU

#define chk(chk,err,ret) if(check_bl(chk)){errno=err; return ret;}

/* vars */
struct dynlist{
  int count;
  char **list;
};

char buff[PATH_MAX];

struct dynlist blacklist;
struct dynlist blacklist_re;
struct dynlist whitelist;
struct dynlist whitelist_re;

char *genname(char *sname, char *kname){
  strcpy(buff,sname);
  strcat(buff,":");
  strcat(buff,kname);
  return buff;
}

void dynlist_init(struct dynlist *l){
  l->count=0;
  l->list=malloc(0);
}

void dynlist_append(struct dynlist *l,char *str){
  int len;
  l->list=realloc(l->list,(l->count+1)*sizeof(int));
  len=strlen(str);
  l->list[l->count]=calloc((size_t)(len+1),sizeof(char));
  strcpy(l->list[l->count],str);
  l->count++;
}

void dynlist_clean(struct dynlist *l){
  for(int i=0;i<l->count;i++){
    free(l->list[i]);
  }
  free(l->list);
  l->count=0;
}

void dynlist_from_str(struct dynlist *l, char *str){
  char *item;
  char tmp[PATH_MAX];

  strcpy(tmp,str);
  item=strtok(tmp," ");
  while(item!=NULL){
    dynlist_append(l,item);
    item=strtok(NULL," ");
  }
}

int dynlist_check(struct dynlist *l,char *path){
  int i;

  for(i=0;i<l->count;i++)
    if(!strcmp(l->list[i],path))
      return 1;
  return 0;
}

int dynlist_checkre(struct dynlist *l,char *path){
  int i;
  regex_t re;

  for(i=0;i<l->count;i++)
    if(!regcomp(&re,l->list[i],REG_EXTENDED))
      if(!regexec(&re,path,(size_t)0,NULL,0))
        return 1;
  return 0;
}

/* original syscalls */
int32_t (*calls_open)(const char *pathname, int flags, mode_t mode); /* !!! DEPRECATED !!!! */
int64_t (*calls_open64)(const char *pathname, int flags, mode_t mode);
ssize_t (*calls_getxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*calls_lgetxattr)(const char *path, const char *name, void *value, size_t size);
int (*calls_bind)(int socket, const struct sockaddr *address, socklen_t address_len);
int (*calls_execve)(const char *filename, char *const argv[], char *const envp[]);

/* constructor */
void __attribute__ ((constructor)) init(void){
  struct group *grp;
  dictionary *config;
  char *username;
  char *groupname;
  char tmplist[PATH_MAX];

  /* init lists */
  dynlist_init(&blacklist);
  dynlist_init(&blacklist_re);
  dynlist_init(&whitelist);
  dynlist_init(&whitelist_re);

  /* get user and group */
  username = getlogin();
  grp = getgrgid(getgid());
  groupname = grp->gr_name;

  /* init config */
  config = iniparser_load(CFGPATH);

  /* generate lists */
  strcpy(buff,"user ");
  strcat(buff,username);
  if(iniparser_find_entry(config,buff)){
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"blacklist"),""));
    dynlist_from_str(&blacklist,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"blacklist_re"),""));
    dynlist_from_str(&blacklist_re,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"whitelist"),""));
    dynlist_from_str(&whitelist,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"whitelist_re"),""));
    dynlist_from_str(&whitelist_re,tmplist);
  }

  strcpy(buff,"group ");
  strcat(buff,groupname);
  if(iniparser_find_entry(config,buff)){
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"blacklist"),""));
    dynlist_from_str(&blacklist,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"blacklist_re"),""));
    dynlist_from_str(&blacklist_re,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"whitelist"),""));
    dynlist_from_str(&whitelist,tmplist);
    strcpy(tmplist,iniparser_getstring(config,genname(buff,"whitelist_re"),""));
    dynlist_from_str(&whitelist_re,tmplist);
  }


  iniparser_freedict(config);

  /* syscalls */
  calls_open=dlsym(RTLD_NEXT, "open"); /* !!! DEPRECATED !!!! */
  calls_open64=dlsym(RTLD_NEXT, "open64");
  calls_getxattr=dlsym(RTLD_NEXT, "getxattr");
  calls_lgetxattr=dlsym(RTLD_NEXT, "lgetxattr");
  calls_bind=dlsym(RTLD_NEXT, "bind");
  calls_execve=dlsym(RTLD_NEXT, "execve");
}

/* destructor */
void __attribute__ ((destructor)) destruct(void){
  /* clear lists */
  dynlist_clean(&blacklist);
  dynlist_clean(&blacklist_re);
  dynlist_clean(&whitelist);
  dynlist_clean(&whitelist_re);
}

int check_bl(const char *pathname){
  char path[PATH_MAX]="";
  int pass=0;

  if(strrchr(pathname,'/')==NULL){
    getcwd(path,PATH_MAX);
    strcat(path,"/");
  }

  strcat(path,pathname);

  /* blacklist */
  if(dynlist_check(&blacklist,path) || dynlist_checkre(&blacklist_re,path))
    pass=1;

  /* whitelist */
  if(dynlist_check(&whitelist,path) || dynlist_checkre(&whitelist_re,path))
    pass=0;

  return pass;
}

/* calls */
int32_t open(const char *pathname, int flags, mode_t mode){  /* !!! DEPRECATED !!!! */
  chk(pathname,EACCES,-1);
  return calls_open(pathname, flags, mode);
}

int64_t open64(const char *pathname, int flags, mode_t mode){
  chk(pathname,EACCES,-1);
  return calls_open64(pathname, flags, mode);
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size){
  chk(path,ENODATA,-1);
  return calls_getxattr(path, name, value, size);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size){
  chk(path,ENODATA,-1);
  return calls_lgetxattr(path, name, value, size);
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len){
  struct sockaddr_in *sock = (struct sockaddr_in *)address;
  char port[6], rulestr[11];

  if(sock->sin_family==AF_INET || sock->sin_family==AF_INET6){
    sprintf(port,"%u",htons(sock->sin_port));
    strcpy(rulestr,"port:");
    strcat(rulestr,port);
    chk(rulestr,EACCES,-1);
  }
  return calls_bind(socket,address,address_len);
}

int execve(const char *filename, char *const argv[], char *const envp[]){
  chk(filename,EACCES,-1);
  return calls_execve(filename,argv,envp);
}
