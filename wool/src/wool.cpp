// wool.cpp -- wool serevr main module (::wool)
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

namespace servant {

}

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
	int (*pack_unclogin)(unsigned char *from, char *username, char *passwd);
	int (*pack_unslogin)(unsigned char *from, int *ret, int *termn);
	int (*pack_unkey)(unsigned char *from, int *special, int *code);
	int (*pack_unclose)(unsigned char *from, char *reason);
	
	int (*wrap_ssend )(woolnet_serv_t *serv, void *buf, size_t len);
	int (*wrap_csend )(woolnet_clnt_t *clnt, void *buf, size_t len);
	int (*wrap_srecv )(woolnet_serv_t *serv, void *buf, size_t len);
	int (*wrap_crecv )(woolnet_clnt_t *clnt, void *buf, size_t len);
	int (*wrap_sclose)(woolnet_serv_t *serv);
	int (*wrap_cclose)(woolnet_clnt_t *clnt);
}

extern "C" int main(int argc, char **args);
static const mfunc_t funcs[] = {
		{(fptr_t)main,                    "main"},
		{NULL,                            NULL}
};

extern "C" int keh_init(kap_t k, ppackage aux)
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
	woolnet::serv_fd =       (int             (*)(woolnet_serv_t*))            fsget((mfunc_t*)woolfs.d.data, "serv_fd");
	woolnet::serv_shut =     (int             (*)(woolnet_serv_t*))            fsget((mfunc_t*)woolfs.d.data, "serv_shut");
	woolnet::clnt_connect =  (woolnet_clnt_t *(*)(char*, int, char*, char*))   fsget((mfunc_t*)woolfs.d.data, "clnt_connect");
	woolnet::clnt_fd =       (int             (*)(woolnet_clnt_t*))            fsget((mfunc_t*)woolfs.d.data, "clnt_fd");
	woolnet::clnt_shut =     (int             (*)(woolnet_clnt_t*))            fsget((mfunc_t*)woolfs.d.data, "clnt_shut");
	woolnet::prot_maxlen =   (int(*)())                                        fsget((mfunc_t*)woolfs.d.data, "prot_maxlen");
	woolnet::pack_clogin =   (int(*)(unsigned char*, char[32], char[32]))      fsget((mfunc_t*)woolfs.d.data, "pack_clogin");
	woolnet::pack_close =    (int(*)(unsigned char*, char[128]))               fsget((mfunc_t*)woolfs.d.data, "pack_close");
	woolnet::pack_key =      (int(*)(unsigned char*, int, int))                fsget((mfunc_t*)woolfs.d.data, "pack_key");
	woolnet::pack_slogin =   (int(*)(unsigned char*, int, int))                fsget((mfunc_t*)woolfs.d.data, "pack_slogin");
	woolnet::pack_unclogin = (int(*)(unsigned char*, char*, char*))            fsget((mfunc_t*)woolfs.d.data, "pack_unclogin");
	woolnet::pack_unclose =  (int(*)(unsigned char*, char*))                   fsget((mfunc_t*)woolfs.d.data, "pack_unclose");
	woolnet::pack_unkey =    (int(*)(unsigned char*, int*, int*))              fsget((mfunc_t*)woolfs.d.data, "pack_unkey");
	woolnet::pack_unslogin = (int(*)(unsigned char*, int*, int*))              fsget((mfunc_t*)woolfs.d.data, "pack_unslogin");
	woolnet::wrap_cclose =   (int(*)(woolnet_clnt_t*))                         fsget((mfunc_t*)woolfs.d.data, "wrap_cclose");
	woolnet::wrap_crecv =    (int(*)(woolnet_clnt_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_crecv");
	woolnet::wrap_csend =    (int(*)(woolnet_clnt_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_csend");
	woolnet::wrap_sclose =   (int(*)(woolnet_serv_t*))                         fsget((mfunc_t*)woolfs.d.data, "wrap_close");
	woolnet::wrap_srecv =    (int(*)(woolnet_serv_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_srecv");
	woolnet::wrap_ssend =    (int(*)(woolnet_serv_t*, void*, size_t))          fsget((mfunc_t*)woolfs.d.data, "wrap_ssend");
	
	return OKAY;
}
extern "C" ppackage keh_knock(ppackage in)
{
	if (kaux_isforme(in.reci))
		return kaux_act(kauxhdl, in);
	else return kaux_pass(kauxhdl, in);
}

extern "C" int main(int argc, char **args)
{
	printf("[wool main(..)] Yay...\n");
	
	woolnet_serv_t *serv = woolnet::serv_listen(7717); // 7717 is the port
	if (!serv) {
		printf("[wool main(..)] failed to create woolnet server\n");
		return ERRBELOW;
	}
	
	unsigned char *buf = new unsigned char[woolnet::prot_maxlen()];
	unsigned char *bufcur; // current position in buffer
	size_t len;
	woolnet_clnt_t *sample_client = new woolnet_clnt_t();
	unsigned int blah_len;
	printf("waiting..\n");
	int clt = woolnet::serv_accept(serv, sample_client, &blah_len);
	printf("got one\n");
	if (clt<0) {
		printf("[wool main(..)] failed to accept sample client\n");
		return ERRBELOW;
	}
	
	len = woolnet::wrap_crecv(sample_client, buf, woolnet::prot_maxlen());
	if (len<=0) {
		printf("[wool main(..)] Failed to receive CLOGIN pack\n");
		return ERR;
	}
	if (buf[0] != PACK_CLOGIN) {
		printf("[wool main(..)] Received unexpected non-CLOGIN packet\n");
		return ERRCAKE;
	}
	char *username = new char[32];
	char *password = new char[32];
	woolnet::pack_unclogin(buf, username, password);
	printf("[wool main(..)] Client '%s' with password '%s'\n", username, password);
	len = woolnet::pack_slogin(buf, PRET_OKAY, 12);
	woolnet::wrap_csend(sample_client, buf, len);
	
	int red; // amount of used bytes by certain package (advnace bufcur by this)
	red = 0;
	bufcur = NULL;
	
	while (1)
	{
		bufcur += red;
		//printf("[wool main(..)] red=%03i buf=%p bufcur=%p\n", red, buf, bufcur);
		red = 0;
		if (!bufcur || bufcur >= buf+len) { // next eventually big piece of data
			len = woolnet::wrap_crecv(sample_client, buf, woolnet::prot_maxlen());
			bufcur = buf;
			if (len<=0) {
				printf("[wool main(..)] wrap_crecv failed\n");
				usleep(1000000);
				continue;
			}
			//printf("[wool main(..) << DATA] len=%i\n", len);
		}
		
		unsigned char type = bufcur[0]; // typechar
		switch (type) {
		case PACK_KEY:
			int special, key;
			woolnet::pack_unkey(bufcur, &special, &key);
			red = woolnet::pack_key(NULL, 0, 0);
			if (special != 0) {
				printf("[wool main(..) << PACK_KEY] special!=0 not supprted\n");
				continue;
			}
			//printf("key: (0x%02x) %c\n", key, key);
			//printf("[wool main(..) << PACK_KEY] 0x%02x key\n", key);
			putchar(key);
			continue;
			
		case PACK_PING:
			printf("WRN [wool main(..) << PACK_PING] ping package not defined... :3\n");
			red = 1;
			continue;
			
		case PACK_CLOSE:
			printf("[wool main(..) << PACK_CLOSE] from sample_client\n");
			char reason[128];
			woolnet::pack_unclose(bufcur, reason);
			red = woolnet::pack_close(NULL, NULL);
			continue;
			
		default:
			printf("[wool main(..) << PACK_???] Unknown packtype 0x%02x\n", type);
			red = 1;
			//usleep(1000000);
			continue;
		}
	}
	
	woolnet::wrap_cclose(sample_client); // might be wrong, why not clnt_shut ?
	woolnet::wrap_sclose(serv);
	
	return OKAY;
}
























