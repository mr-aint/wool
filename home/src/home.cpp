// home.cpp -- home

#include <cstdio>
#include <cstdlib>

#include <keh.h>
#include <kaux.h>

void *kauxhdl;
kap_t keh;
static const mfunc_t extfuncs[] = {
		{(fptr_t)NULL,                    NULL},
};
extern "C" int keh_init(kap_t k, ppackage aux)
{
	kauxhdl = kaux_newhandle(k);
	keh = k;
	
	kaux_setfuncs(kauxhdl, (mfunc_t*)extfuncs);
	
	return OKAY;
}
extern "C" ppackage keh_knock(ppackage p, void *aux)
{
	if (kaux_isforme(p.reci)) kaux_act(kauxhdl, p);
	else                      kaux_pass(kauxhdl, p);
}

int user_new(char *name)
{
	return ERRNIMPL;
}





