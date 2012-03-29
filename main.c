/*
 * Application:   MIU - MAC In Userspace
 * Author: thc_flow
 *
 * Created on October 21, 2011, 9:56 AM
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivs 3.0 Unported License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/3.0/ or send a letter to
 * Creative Commons, 444 Castro Street, Suite 900, Mountain View, California, 94041, USA.
 */

#define CFGPATH "/etc/miu.conf"

//Basic includes
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

//dlsym
#define __USE_GNU
#include <dlfcn.h>

//configuration
#include <libconfig.h>
#include <regex.h>

#ifdef EBUG
  #define TRACE(x) fprintf(stderr,"[%s]\n",x); fflush(stderr)
#else
  #define TRACE(x)
#endif

#define chk(chk,err,ret) if(check_bl(chk)){errno=err; return ret;}

//structure for libconfig
struct config_t cfg;

//original syscalls struct
struct {
  int (*open)(const char *pathname, int flags, mode_t mode);
  int (*open64)(const char *pathname, int flags, mode_t mode);
  struct __dirstream *(*opendir)(const char *name);

  ssize_t (*getxattr)(const char *path, const char *name, void *value, size_t size);
  ssize_t (*lgetxattr)(const char *path, const char *name, void *value, size_t size);

  int (*bind)(int socket, const struct sockaddr *address, socklen_t address_len);

  int (*execve)(const char *filename, char *const argv[], char *const envp[]);
} calls;

//constructor
void __attribute__ ((constructor)) init(void){
  TRACE("Loading MIU");
  //init && read config
  TRACE("Loading config...");
  config_init(&cfg);
  if(!config_read_file(&cfg, CFGPATH)){
    fprintf(stderr,"[%s:%i %s]\n",config_error_file(&cfg),config_error_line(&cfg),config_error_text(&cfg));
  }

  //syscalls
  TRACE("Linking calls table");
  calls.open=dlsym(RTLD_NEXT, "open");
  calls.open64=dlsym(RTLD_NEXT, "open64");
  calls.opendir=dlsym(RTLD_NEXT, "opendir");

  calls.getxattr=dlsym(RTLD_NEXT, "getxattr");
  calls.lgetxattr=dlsym(RTLD_NEXT, "lgetxattr");

  calls.bind=dlsym(RTLD_NEXT, "bind");

  calls.execve=dlsym(RTLD_NEXT, "execve");
}

//destructor
void __attribute__ ((destructor)) destruct(void){
  TRACE("Unloading MIU");
  //free config
  config_destroy(&cfg);
}

//helpers
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
  config_setting_t *rootcfg=NULL,*rolecfg=NULL, *subcfg=NULL; //root "config", roles, subs (gid/blaclist/etc...)
  char path[1024];

  getabspath(pathname,path);

  if((rootcfg=config_lookup(&cfg,"config"))!=NULL) //lookup for config=[
    for(i=0;i<config_setting_length(rootcfg);i++){  //for i in {...};{...};
      if((rolecfg=config_setting_get_elem(rootcfg,i))){  //get role

        if((subcfg=config_setting_get_member(rolecfg,"gid"))!=NULL){ //get gid
          gid=config_setting_get_int(subcfg);
        }

        if((subcfg=config_setting_get_member(rolecfg,"uid"))!=NULL){ //get uid
          uid=config_setting_get_int(subcfg);
        }


        if(gid==(int)getgid() || uid==(int)getuid()){  //compare

          //blacklist
                if(check(rolecfg,"blacklist",path) || checkre(rolecfg,"blacklist_regexp",path))
                  pass=1;

          //whitelist
                if(check(rolecfg,"whitelist",path) || checkre(rolecfg,"whitelist_regexp",path))
                  pass=0;
        }
      }
    }
  return pass;
}


//calls
int open(const char *pathname, int flags, mode_t mode){
  chk(pathname,EACCES,-1);
  return calls.open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, mode_t mode){
  chk(pathname,EACCES,-1);
  return calls.open64(pathname, flags, mode);
}

struct __dirstream *opendir(const char *name){
  chk(name,EACCES,NULL);
  return calls.opendir(name);
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size){
  chk(path,ENODATA,-1);
  return calls.getxattr(path, name, value, size);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size){
  chk(path,ENODATA,-1);
  return calls.lgetxattr(path, name, value, size);
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
  return calls.bind(socket,address,address_len);
}

int execve(const char *filename, char *const argv[], char *const envp[]){
  chk(filename,EACCES,-1);
  return calls.execve(filename,argv,envp);
}
