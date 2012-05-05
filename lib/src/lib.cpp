// lib.cpp -- lib (::lib) module to contain all the api.
#include <stdio.h>
#include <stdlib.h>

#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>

#include <keh.h>
#include <kaux.h>

#include <woolnet.h>

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
	
	kaux_meta(kauxhdl, "pthread", "libpthread"); // ::lib::pthread
	// list more libs here
	
	// selfknock create directory
	//keh_knock(ppnstuff(NULL, "pub", DAFUQ));
	
	
	
	return OKAY;
}
ppackage keh_knock(ppackage in)
{
	if (kaux_isforme(in.reci))
		return kaux_act(kauxhdl, in);
	else return kaux_pass(kauxhdl, in);
}
















}





















