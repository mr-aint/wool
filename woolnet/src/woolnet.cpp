// woolnet.cpp -- woolnet
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <keh.h>
#include <kaux.h>

#include <woolnet.h>

using namespace std;

kap_t kap;
void *kauxhdl;

extern "C" {

woolnet_serv_t *serv_listen(int port);
int             serv_accept(woolnet_serv_t *serv, woolnet_clnt_t *client, unsigned int *len);
int             serv_fd(woolnet_serv_t *self);
int             serv_shut(woolnet_serv_t *serv);

woolnet_clnt_t *clnt_connect(char *host, int port, char *username, char *passw);
int             clnt_fd(woolnet_clnt_t *self);
int             clnt_shut(woolnet_clnt_t *self);

int prot_maxlen();
int pack_clogin(unsigned char *into, char username[32], char passwd[32]);
int pack_slogin(unsigned char *into, int ret, int termn);
int pack_key(unsigned char *into, int special, int code);
int pack_close(unsigned char *into, char reason[128]);
int pack_unclogin(unsigned char *from, char *username[32], char *passwd[32]);
int pack_unslogin(unsigned char *from, int *ret, int *termn);
int pack_unkey(unsigned char *from, int *special, int *code);
int pack_unclose(unsigned char *from, char *reason[128]);

int wrap_ssend(woolnet_serv_t *serv, void *buf, size_t len);
int wrap_csend(woolnet_clnt_t *clnt, void *buf, size_t len);
int wrap_srecv(woolnet_serv_t *serv, void *buf, size_t len);
int wrap_crecv(woolnet_clnt_t *clnt, void *buf, size_t len);
int wrap_sclose(woolnet_serv_t *serv);
int wrap_cclose(woolnet_clnt_t *clnt);

static const mfunc_t funcs[] = {
		{(fptr_t)serv_listen,             "serv_listen"},
		{(fptr_t)serv_accept,             "serv_accept"},
		{(fptr_t)serv_fd,                 "serv_fd"},
		{(fptr_t)serv_shut,               "serv_shut"},

		{(fptr_t)clnt_connect,            "clnt_connect"},
		{(fptr_t)clnt_fd,                 "clnt_fd"},
		{(fptr_t)clnt_shut,               "clnt_shut"},
		
		{(fptr_t)prot_maxlen,             "prot_maxlen"},
		{(fptr_t)pack_clogin,             "pack_clogin"},
		{(fptr_t)pack_slogin,             "pack_slogin"},
		{(fptr_t)pack_key,                "pack_key"},
		{(fptr_t)pack_close,              "pack_close"},
		{(fptr_t)pack_unclogin,           "pack_unclogin"},
		{(fptr_t)pack_unslogin,           "pack_unslogin"},
		{(fptr_t)pack_unkey,              "pack_unkey"},
		{(fptr_t)pack_unclose,            "pack_unclose"},

		{(fptr_t)wrap_ssend,              "wrap_ssend"},
		{(fptr_t)wrap_srecv,              "wrap_srecv"},
		{(fptr_t)wrap_sclose,             "wrap_sclose"},
		{(fptr_t)wrap_csend,              "wrap_csend"},
		{(fptr_t)wrap_crecv,              "wrap_crecv"},
		{(fptr_t)wrap_cclose,             "wrap_cclose"},
		{NULL,                            NULL},
};
int keh_init(kap_t k, ppackage aux)
{
	kap = k;
	kauxhdl = kaux_newhandle(k);
	kaux_setfuncs(kauxhdl, (mfunc_t*)funcs);
	kaux_setobj(kauxhdl, NULL);
	kaux_settyp(kauxhdl, NULL);
	
	/*// ::bar
	//_bar.iadd = fsget(kap.knock(ppfuncs("::bar")), "iadd");
	ppackage barfs = kap.knock(ppfuncs("::bar"));
	if (barfs.type != 'd') return ERRNCARE;
	_bar.iadd = fsget((mfunc_t*)barfs.d.data, "iadd");
	printf("[foo init] &::bar->iadd = %p\n", _bar.iadd); */
	
	return OKAY;
}
ppackage keh_knock(ppackage in)
{
	if (kaux_isforme(in.reci))
		return kaux_act(kauxhdl, in);
	else return kaux_pass(kauxhdl, in);
}



// starts a new server instance
woolnet_serv_t *serv_listen(int port)
{
	woolnet_serv_t *serv = new woolnet_serv_t();
	
	if ((serv->sodex = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		delete serv;
		printf("[woolnet serv_listen(..)] Failed to allocate socket fd\n");
		return NULL;
	}
	
	sockaddr_in *saddr = new sockaddr_in();
	memset(saddr, 0, sizeof(sockaddr_in));
	saddr->sin_family = AF_INET;
	saddr->sin_addr.s_addr = htonl(INADDR_ANY);
	saddr->sin_port = htons(port);
	
	if (bind(serv->sodex, (sockaddr*)saddr, sizeof(sockaddr_in)) < 0) {
		delete serv;
		delete saddr;
		printf("[woolnet serv_listen(..)] Failed to bind socket\n");
		return NULL;
	}
	
	if (listen(serv->sodex, 5) < 0) {
		delete serv;
		delete saddr;
		printf("[woolnet serv_listen(..)] Failed to set listening-mode\n");
		return NULL;
	}
	
	printf("[woolnet serv_listen(..)] Successfully created new serv\n");
	
	return serv;
}
// returns sockfd of client, writes essential information into nullar &client.
// make len be a pointer to empty unsigned int, because POSIX accept(..) reqs.!
// This does not perform any additional networking/packetint! (direct wrapper)
int serv_accept(woolnet_serv_t *serv, woolnet_clnt_t *client, unsigned int *len)
{
	return (client->sodex=accept(serv->sodex, (sockaddr*)(client->saddr), len));
}
// get filedescriptor of socket
int serv_fd(woolnet_serv_t *self) { return self?self->sodex:NULL; }
// stops listening and destructs (free(..)) handle. (if returns ERR handle aliv)
int serv_shut(woolnet_serv_t *serv)
{
	if (!serv) return ERRRUBBISH;
	
	int closeret = close(serv->sodex);
	if (closeret < 0) return ERR;
	delete serv;
	return closeret;
}

// return client handle when successfully connected, else NULL
woolnet_clnt_t *clnt_connect(char *host, int port, char *username, char *passw)
{
	woolnet_clnt_t *clnt = new woolnet_clnt_t();
	sockaddr_in *saddr = new sockaddr_in();
	clnt->saddr = saddr;
	
	
	if ((clnt->sodex = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		delete clnt;
		delete saddr;
		printf("[woolnet clnt_connect(..)] Failed to allocate socket\n");
		return NULL;
	}
	
	unsigned long tmp1;
	
	memset(&clnt->saddr, 0, sizeof(sockaddr_in));
	if ((tmp1 = inet_addr(host)) != INADDR_NONE) {
		memcpy(&saddr->sin_addr, &tmp1, sizeof(tmp1));
	} else {
		hostent *hostinfo = gethostbyname(host);
		if (!hostinfo) {
			printf("[woolnet clnt_connect(..)] Failed to get host by name\n");
			close(clnt->sodex);
			delete clnt;
			delete saddr;
		}
		memcpy(&saddr->sin_addr, hostinfo->h_addr, 
				hostinfo->h_length);
	}
	
	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(port);
	
	if (connect(clnt->sodex,(sockaddr*)saddr,sizeof(sockaddr_in))<0) {
		printf("[woolnet clnt_connect(..)] Failed to connect TCP\n");
		close(clnt->sodex);
		delete clnt;
		delete saddr;
	}
	
	void *buf = (void*)new char[prot_maxlen()];
	int len = pack_clogin((unsigned char*)buf, username, passw);
	if (wrap_csend(clnt, buf, len) != len) {
		printf("[woolnet clnt_connect(..)] Failed send login pack\n");
		close(clnt->sodex);
		delete clnt;
		delete saddr;
	}
	
	len = wrap_crecv(clnt, buf, prot_maxlen());
	if (len<=0) {
		printf("[woolnet clnt_connect(..)] slogin pack recv error\n");
		close(clnt->sodex);
		delete clnt;
		delete saddr;
	}
	
	int sret;
	printf("DBG [woolnet clnt_connect(..)] Before pack_unslogin()..\n");
	pack_unslogin((unsigned char*)buf, &sret, &clnt->termn);
	printf("[woolnet clnt_connect(..)] sret=%i, termn=%i\n", sret, clnt->termn);
	
	return clnt;
}
// get filedescriptor of socket
int clnt_fd(woolnet_clnt_t *self) { return self?self->sodex:NULL; }
// kill the connection
int clnt_shut(woolnet_clnt_t *self)
{
	if (!self) return ERRRUBBISH;
	if (close(self->sodex) < 0) return ERRBELOW;
	return OKAY;
}

// maximal package length
int prot_maxlen() { return 256; }
// username 31 chars + NUL, passwd the same. into must be at least prot_maxlen()
int pack_clogin(unsigned char *into, char username[32], char passwd[32])
{
	if (!into) return 0;
	into[0] = PACK_CLOGIN;
	
	memset(into+1, 0, 32*2);
	memcpy(into+1, username, 32);
	memcpy(into+1+32, passwd, 32);
	
	return 1+32+32;
}
// ret is retcode, termn is the terminal number. currently useless
int pack_slogin(unsigned char *into, int ret, int termn)
{
	if (!into) return 0;
	into[0] = PACK_SLOGIN;
	
	memcpy(into+1, &ret, sizeof(ret));                 // at 1, 8 bytes
	memcpy(into+1+sizeof(ret), &termn, sizeof(termn)); // at 9, 8 bytes
	
	return 1+8+8;
}
// for now you can ignore special.
int pack_key(unsigned char *into, int special, int code)
{
	if (!into) return 0;
	into[0] = PACK_KEY;
	
	memcpy(into+1, &special, sizeof(special));           // at 1, 8 bytes
	memcpy(into+1+sizeof(special), &code, sizeof(code)); // at 9, 8 bytes
	
	return 1+8+8;
}
// reason is human readable as you can see.
int pack_close(unsigned char *into, char reason[128])
{
	if (!into) return 0;
	into[0] = PACK_CLOSE;
	
	memcpy(into+1, reason, 128);
	
	return 1+128;
}

int pack_unclogin(unsigned char *from, char *username[32], char *passwd[32])
{
	if (!from) return ERRRUBBISH;
	if (from[0] != PACK_CLOGIN) return ERRRUBBISH;
	
	memcpy(username, from+1, 32);
	memcpy(passwd, from+1+32, 32);
	
	return OKAY;
}
int pack_unslogin(unsigned char *from, int *ret, int *termn)
{
	if (!from) return ERRRUBBISH;
	if (from[0] != PACK_SLOGIN) return ERRRUBBISH;
	
	memcpy(ret, from+1, 8);
	memcpy(termn, from+1+8, 8);
	
	return OKAY;
}
int pack_unkey(unsigned char *from, int *special, int *code)
{
	if (!from) return ERRRUBBISH;
	if (from[0] != PACK_KEY) return ERRRUBBISH;
	
	memcpy(special, from+1, 8);
	memcpy(code, from+1+8, 8);
	
	return OKAY;
}
int pack_unclose(unsigned char *from, char *reason[128])
{
	if (!from) return ERRRUBBISH;
	if (from[0] != PACK_CLOGIN) return ERRRUBBISH;
	
	memcpy(reason, from+1, 128);
	
	return OKAY;
}

int wrap_ssend(woolnet_serv_t *serv, void *buf, size_t len) {
	return send(serv->sodex, buf, len, 0);
}
int wrap_csend(woolnet_clnt_t *clnt, void *buf, size_t len) {
	return send(clnt->sodex, buf, len, 0);
}
int wrap_srecv(woolnet_serv_t *serv, void *buf, size_t len) {
	return recv(serv->sodex, buf, len, 0);
}
int wrap_crecv(woolnet_clnt_t *clnt, void *buf, size_t len) {
	return recv(clnt->sodex, buf, len, 0);
}
int wrap_sclose(woolnet_serv_t *serv) {
	return close(serv->sodex);
}
int wrap_cclose(woolnet_clnt_t *clnt) {
	return close(clnt->sodex);
}


}















