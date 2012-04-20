// youput.cpp -- woolnet client
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

namespace woolnet {
	woolnet_serv_t *(*serv_listen)(int port);
	int             (*serv_accept)(woolnet_serv_t *serv, woolnet_clnt_t *client, unsigned int *len);
	int             (*serv_fd)(woolnet_serv_t *serv);
	int             (*serv_shut)(woolnet_serv_t *serv);
	
	woolnet_clnt_t *(*clnt_connect)(char *host, int port, char *username, char *passw);
	int             (*clnt_fd)(woolnet_clnt_t *serv);
	int             (*clnt_shut)(woolnet_clnt_t *self);
	
	int (*prot_maxlen)();
	int (*pack_clogin)(unsigned char *into, char username[32], char passwd[32]);
	int (*pack_slogin)(unsigned char *into, int ret, int termn);
	int (*pack_key)(unsigned char *into, int special, int code);
	int (*pack_close)(unsigned char *into, char reason[128]);
	int (*pack_unclogin)(unsigned char *from, char *username[32], char *passwd[32]);
	int (*pack_unslogin)(unsigned char *from, int *ret, int *termn);
	int (*pack_unkey)(unsigned char *from, int *special, int *code);
	int (*pack_unclose)(unsigned char *from, char *reason[128]);
	
	int (*wrap_ssend )(woolnet_serv_t *serv, void *buf, size_t len);
	int (*wrap_csend )(woolnet_clnt_t *clnt, void *buf, size_t len);
	int (*wrap_srecv )(woolnet_serv_t *serv, void *buf, size_t len);
	int (*wrap_crecv )(woolnet_clnt_t *clnt, void *buf, size_t len);
	int (*wrap_sclose)(woolnet_serv_t *serv);
	int (*wrap_cclose)(woolnet_clnt_t *clnt);
}

int main(int argc, char **args);
static const mfunc_t funcs[] = {
		{(fptr_t)main,                    "main"},
		{NULL,                    NULL}
};
int keh_init(kap_t k, ppackage aux)
{
	kap = k;
	kauxhdl = kaux_newhandle(k);
	kaux_setfuncs(kauxhdl, (mfunc_t*)funcs);
	kaux_setobj(kauxhdl, NULL);
	kaux_settyp(kauxhdl, NULL);
	
	ppackage woolfs = kap.knock(ppfuncs("::woolnet"));
	if (woolfs.type != 'd') return ERRNCARE;
	woolnet::serv_accept =   (int             (*)(woolnet_serv_t *, woolnet_clnt_t *, unsigned int *))(fsget((mfunc_t*)woolfs.d.data, "serv_accept"));
	woolnet::serv_listen =   (woolnet_serv_t *(*)(int port))                   fsget((mfunc_t*)woolfs.d.data, "serv_listen");
	woolnet::serv_fd =       (int(*)(woolnet_serv_t*))                         fsget((mfunc_t*)woolfs.d.data, "serv_fd");
	woolnet::serv_shut =     (int             (*)(woolnet_serv_t*))            fsget((mfunc_t*)woolfs.d.data, "serv_shut");
	woolnet::clnt_connect =  (woolnet_clnt_t *(*)(char*, int, char*, char*))   fsget((mfunc_t*)woolfs.d.data, "clnt_connect");
	woolnet::clnt_fd =       (int(*)(woolnet_clnt_t*))                         fsget((mfunc_t*)woolfs.d.data, "clnt_fd");
	woolnet::clnt_shut =     (int             (*)(woolnet_clnt_t*))            fsget((mfunc_t*)woolfs.d.data, "clnt_shut");
	woolnet::prot_maxlen =   (int             (*)())                           fsget((mfunc_t*)woolfs.d.data, "prot_maxlen");
	woolnet::pack_clogin =   (int(*)(unsigned char*, char[32], char[32]))      fsget((mfunc_t*)woolfs.d.data, "pack_clogin");
	woolnet::pack_close =    (int(*)(unsigned char*, char[128]))               fsget((mfunc_t*)woolfs.d.data, "pack_close");
	woolnet::pack_key =      (int(*)(unsigned char*, int, int))                fsget((mfunc_t*)woolfs.d.data, "pack_key");
	woolnet::pack_slogin =   (int(*)(unsigned char*, int, int))                fsget((mfunc_t*)woolfs.d.data, "pack_slogin");
	woolnet::pack_unclogin = (int(*)(unsigned char*, char*[32], char*[32]))    fsget((mfunc_t*)woolfs.d.data, "pack_unclogin");
	woolnet::pack_unclose =  (int(*)(unsigned char*, char*[128]))              fsget((mfunc_t*)woolfs.d.data, "pack_unclose");
	woolnet::pack_unkey =    (int(*)(unsigned char*, int*, int*))              fsget((mfunc_t*)woolfs.d.data, "pack_unkey");
	woolnet::pack_unslogin = (int(*)(unsigned char*, int*, int*))              fsget((mfunc_t*)woolfs.d.data, "pack_unslogin");
	woolnet::wrap_cclose =   (int(*)(woolnet_clnt_t*))                         fsget((mfunc_t*)woolfs.d.data, "wrap_cclose");
	woolnet::wrap_crecv =    (int(*)(woolnet_clnt_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_crecv");
	woolnet::wrap_csend =    (int(*)(woolnet_clnt_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_csend");
	woolnet::wrap_sclose =   (int(*)(woolnet_serv_t*))                         fsget((mfunc_t*)woolfs.d.data, "wrap_close");
	woolnet::wrap_srecv =    (int(*)(woolnet_serv_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_srecv");
	woolnet::wrap_ssend =    (int(*)(woolnet_serv_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_ssend");
	
	printf("DBG [youput keh_init(..)] pick clnt_connect=%p\n", woolnet::clnt_connect);
	
	return OKAY;
}
ppackage keh_knock(ppackage in)
{
	if (kaux_isforme(in.reci))
		return kaux_act(kauxhdl, in);
	else return kaux_pass(kauxhdl, in);
}

int main(int argc, char **args)
{
	char *host = "localhost";
	int port = 7717;
	char username[32] = "imacake"; // TODO seriously, hardcoded username not gd.
	char passwd[32] = "imacakepw"; // TODO seriously, hardcoded password......!
	woolnet_clnt_t *clnt;
	void *buf = (void*)new char[woolnet::prot_maxlen()];
	fd_set evr, ev; // stdin and connection
	
	ev = FD_ZERO(&ev);
	
	
	printf("User: %s\n", username);
	printf("Pwrd: ");
	std::string password = "";
	
	
	
	printf("[youput main(..)] Connecting as '%s'..\n", username);
	
	clnt = woolnet::clnt_connect(host, port, username, passwd);
	if (!clnt) {
		printf("[youput main(..)] Failed to connect.\n");
		exit(-1);
	}
	
	printf("[youput main(..)] You're on terminal number %i\n\n", clnt->termn);
	
	
	
	
	return OKAY;
}






































