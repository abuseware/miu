/* Application: MIU - MAC In Userspace
 * Author: thc_flow
 *
 * Created on October 21, 2011, 9:56 AM
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 Unported License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/3.0/ or send a letter to
 * Creative Commons, 444 Castro Street, Suite 900, Mountain View, California, 94041, USA.
 */


/* HEEEEY, LOOK HERE! */
#define CFGPATH "/etc/miu.conf"
/* OK, NOW GTFO */

/* oldfags */
#include <unistd.h>
#include <stdlib.h>
/* errno */
#include <errno.h>
/* bind */
#include <sys/socket.h>
#include <netinet/in.h>
/* int*_t */
#include <linux/types.h>
/* typedef DIR */
#define _GNU_SOURCE
#define __USE_LARGEFILE64
  #include <dirent.h>
#undef __USE_LARGEFILE64
#undef _GNU_SOURCE
/* config */
#include <libconfig.h>
#include <stdio.h>
#include <regex.h>
#include <string.h>
/* dlsym */
#define __USE_GNU
  #include <dlfcn.h>
#undef __USE_GNU

#define chk(chk,err,ret) if(check_bl(chk)){errno=err; return ret;}

/* vars */
struct config_t cfg;
char lastdirname[PATH_MAX];

/* original syscalls */
int32_t (*calls_open)(const char *pathname, int flags, mode_t mode); /* !!! DEPRECATED !!!! */
int64_t (*calls_open64)(const char *pathname, int flags, mode_t mode);
DIR *(*calls_opendir)(const char *name);
struct dirent *(*calls_readdir)(DIR *dirp);
struct dirent64 *(*calls_readdir64)(DIR *dirp);
ssize_t (*calls_getxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*calls_lgetxattr)(const char *path, const char *name, void *value, size_t size);
int (*calls_bind)(int socket, const struct sockaddr *address, socklen_t address_len);
int (*calls_execve)(const char *filename, char *const argv[], char *const envp[]);

/* constructor */
void __attribute__ ((constructor)) init(void){
  /* init && read config */
  config_init(&cfg);
  if(!config_read_file(&cfg, CFGPATH)){
    fprintf(stderr,"[%s:%i %s]\n",config_error_file(&cfg),config_error_line(&cfg),config_error_text(&cfg));
  }

  /* syscalls */
  calls_open=dlsym(RTLD_NEXT, "open"); /* !!! DEPRECATED !!!! */
  calls_open64=dlsym(RTLD_NEXT, "open64");
  calls_readdir=dlsym(RTLD_NEXT, "readdir");
  calls_readdir64=dlsym(RTLD_NEXT, "readdir64");
  calls_opendir=dlsym(RTLD_NEXT, "opendir");
  calls_getxattr=dlsym(RTLD_NEXT, "getxattr");
  calls_lgetxattr=dlsym(RTLD_NEXT, "lgetxattr");
  calls_bind=dlsym(RTLD_NEXT, "bind");
  calls_execve=dlsym(RTLD_NEXT, "execve");
}

/* destructor */
void __attribute__ ((destructor)) destruct(void){
  /* free config */
  config_destroy(&cfg);
}

/* helpers */
int check(config_setting_t *config, const char *table, const char *value){
  int i;
  config_setting_t *subcfg=NULL;

  if((subcfg=config_setting_get_member(config,table))!=NULL)
    for(i=0;i<config_setting_length(subcfg);i++)
      if(!strcmp(config_setting_get_string_elem(subcfg,i),value))
        return 1;
  return 0;
}

int checkre(config_setting_t *config, const char *table, const char *value){
  int i;
  config_setting_t *subcfg=NULL;
  regex_t re;

  if((subcfg=config_setting_get_member(config,table))!=NULL)
    for(i=0;i<config_setting_length(subcfg);i++)
      if(!regcomp(&re,config_setting_get_string_elem(subcfg,i),REG_EXTENDED))
        if(!regexec(&re,value,(size_t)0,NULL,0))
          return 1;
  return 0;
}

void getabspath(const char *path, char *dest){
  char oldcwd[1024];
  char *spos;

  spos=strrchr(path,'/');
  memset(dest,0,sizeof(dest-1));
  if(spos!=NULL){
    strncpy(dest,path,spos-path);
    if(!access(dest,F_OK)){
      getcwd(oldcwd,sizeof(oldcwd)-1);
      chdir(dest);
      getcwd(dest,sizeof(dest)-1);
      chdir(oldcwd);
      strcat(dest,spos);
    } else strcpy(dest,path);
  } else strcpy(dest,path);
}

int check_bl(const char *pathname){
  int i;
  int gid=-1, uid=-1, pass=0;
  config_setting_t *rootcfg=NULL,*rolecfg=NULL, *subcfg=NULL; /* root "config", roles, subs (gid/blaclist/etc...) */
  char path[1024];

  getabspath(pathname,path);

  if((rootcfg=config_lookup(&cfg,"config"))!=NULL) /* lookup for config=[ */
    for(i=0;i<config_setting_length(rootcfg);i++){  /* for i in {...};{...}; */
      if((rolecfg=config_setting_get_elem(rootcfg,i))){  /* get role */

        if((subcfg=config_setting_get_member(rolecfg,"gid"))!=NULL){ /* get gid */
          gid=config_setting_get_int(subcfg);
        }

        if((subcfg=config_setting_get_member(rolecfg,"uid"))!=NULL){ /* get uid */
          uid=config_setting_get_int(subcfg);
        }


        if(gid==(int)getgid() || uid==(int)getuid()){  /* compare */

          /* blacklist */
                if(check(rolecfg,"blacklist",path) || checkre(rolecfg,"blacklist_regexp",path))
                  pass=1;

          /* whitelist */
                if(check(rolecfg,"whitelist",path) || checkre(rolecfg,"whitelist_regexp",path))
                  pass=0;
        }
      }
    }
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

DIR *opendir(const char *name){
  chk(name,EACCES,NULL);
  strcpy(lastdirname,name);
  return calls_opendir(name);
}

struct dirent *readdir(DIR *dirp){
  struct dirent *d;
  char fullname[PATH_MAX];
  if((d=calls_readdir(dirp))!=NULL){
    strcpy(fullname,lastdirname);
    strcat(fullname,"/");
    strcat(fullname,d->d_name);
    if((strcmp(d->d_name,".") && strcmp(d->d_name,"..") && check_bl(fullname)) || !strcmp(fullname,CFGPATH)){
      d=calls_readdir(dirp);
    }
  }
  return d;
}

struct dirent64 *readdir64(DIR *dirp){
  struct dirent64 *d;
  char fullname[PATH_MAX];
  if((d=calls_readdir64(dirp))!=NULL){
    strcpy(fullname,lastdirname);
    strcat(fullname,"/");
    strcat(fullname,d->d_name);
    if((strcmp(d->d_name,".") && strcmp(d->d_name,"..") && check_bl(fullname)) || !strcmp(fullname,CFGPATH)){
      d=calls_readdir64(dirp);
    }
  }
  return d;
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
