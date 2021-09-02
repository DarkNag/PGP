#ifndef DEF_RSA
#define DEF_RSA

#define MAX_SIZE 4000
#define MSG_SIZE 10000
#define BASE 16
#define BASE_IN 16
#define RSA_T1 300

void date(int *year,int *mon, int *day);
void chiffrerRSA(mpz_t n,mpz_t e,char *nom_fichier);
void dechiffrerRSA(mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv,char *nom_fichier);
void generate_sessionkey(int nbits,mpz_t k);
void print_session(mpz_t k);
void generate_RSAkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv);
void print_userid(int argc, char *argv[],mpz_t keyID,int ln,int lm, int lc, char *nom,char *mail, char *comment);
void print_pubkey(int argc, char *argv[],int year,int mon,int day,int nbits,mpz_t n,mpz_t e);
void get_pubkey(int argc, char *argv[],int nbits,mpz_t n,mpz_t e);
void get_pubkeyring(int argc, char *argv[],int nbits,mpz_t n,mpz_t e);
void print_privkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv);
void get_privkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv);
void get_privkeyring(int argc, char *argv[],int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv);


#endif 
