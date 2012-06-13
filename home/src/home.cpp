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
static const mfunc_t meuserfuncs[] = {
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

int user_new(char *username)
{
	printf("WARN [home user_new(\"%s\")] Not checking for taken username\n", username);
	
	ppackage ppout1;
	ppout1.type = 'n'; // named stuff
	ppout1.reci = "::home"; // should be self.
	ppout1.n.name = username;
	ppout1.n.knockf = kaux_knockaux;
	ppout1.n.aux = kaux_newhandle(keh);
	kaux_setfuncs(ppout1.n.aux, (mfunc_t*)meuserfuncs);
	kaux_setobj(ppout1.n.aux, ppout1.n.aux);
	keh.knock(ppout1, NULL);
	
	return OKAY;
}

int userf_init(kap_t k, ppackage aux)
{
	
}

// used to setup a ::home::username 
//mfunc_t *gimme_meuserfuncs() { return meuserfuncs; }





