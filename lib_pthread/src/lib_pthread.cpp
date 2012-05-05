// lib_pthread.cpp -- ::lib::pthread POSIX threads library wrapper module
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h>
#include <string>

#include <pthread.h>

#include <keh.h>
#include <kaux.h>

kap_t kap;
void *kauxhdl;

extern "C" {

ppackage keh_knock(ppackage in);
int main(int argc, char **args);
static const mfunc_t funcs[] = {
		{(fptr_t)main,                    "main"},
		{NULL,                            NULL}
};
int keh_init(kap_t k, ppackage aux)
{
	kap = k;
	kauxhdl = kaux_newhandle(k);
	kaux_setfuncs(kauxhdl, (mfunc_t*)funcs);
	kaux_setobj(kauxhdl, NULL);
	kaux_settyp(kauxhdl, NULL);
	
	return OKAY;
}
ppackage keh_knock(ppackage in)
{
	if (kaux_isforme(in.reci))
		return kaux_act(kauxhdl, in);
	else return kaux_pass(kauxhdl, in);
}

int pthread_create(pthread_t * thread, 
                   const pthread_attr_t * attr,
                   void * (*start_routine)(void *), 
                   void *arg)
{
	
}





}































