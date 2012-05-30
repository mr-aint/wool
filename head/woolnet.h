// woolnet.h -- decls for woolnet module

typedef struct woolnet_clnt_s
{
	int sodex;
	void *saddr;
	
	int termn;
	
	char *username;
	char passwd[32];
	
} woolnet_clnt_t;

typedef struct woolnet_serv_s
{
	int sodex;
	void *saddr;
	
} woolnet_serv_t;




// packet first bytes
enum {
	PACK_PING = 0,
	PACK_CLOGIN = 1,
	PACK_SLOGIN,
	PACK_KEY,
	PACK_CLOSE,
};

// return codes inside packages
enum {
	PRET_OKAY = 0,
	PRET_PWRONG, // wrong password
	PRET_NOUSER, // user does not exist
	PRET_INTERN, // error inside.
};
