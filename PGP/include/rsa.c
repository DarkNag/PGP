#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>
#include <string.h>

#include "rsa.h"

void date(int *year,int *mon, int *day)
{
	time_t t;
    struct tm *tb;
	t = time(NULL);
    tb = localtime(&t);
	
	*year=tb->tm_year+1900;
	*mon=tb->tm_mon+1;
	*day=tb->tm_mday;
}

// m est le message à chiffrer, (n,e) la clé publique 
void chiffrerRSA(mpz_t n,mpz_t e,char *nom_fichier)
{
	int cmp;
	mpz_t m,c;
	mpz_inits(m,c,NULL);

	FILE* fichier_in = NULL;
	FILE* fichier_out = NULL;

	fichier_in = fopen(nom_fichier, "r");
	if(fichier_in != NULL)
	{
		char str[MAX_SIZE];
		fgets(str, MAX_SIZE, fichier_in);
		mpz_set_str(m, str, BASE_IN);
	}
	
	cmp=mpz_cmp(n,m); 
	if(!(cmp>0)) // si m n'est pas entre 0 et n-1
		printf("Error : message representative out of range\n");
	else
	{		
		mpz_powm(c,m,e,n);
		fichier_out = fopen("keyout.dat", "w");
		if(fichier_out != NULL)
		{
			gmp_fprintf(fichier_out,"%0256Zx\n",c);			
			/*char * _c = mpz_get_str(NULL, BASE, c);
			fputs(_c, fichier_out);
			free(_c);*/
		}		
		//gmp_printf("message chiffré = %Zd\n",c);
	}
	
	fclose(fichier_in);	
	fclose(fichier_out);
	mpz_clear(m);
	mpz_clear(c);
}

void dechiffrerRSA(mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv,char *nom_fichier)
{
	int cmp;
	mpz_t c,n,m,m1,m2,h;
	mpz_inits(c,n,m,m1,m2,h,NULL);	
	
	FILE* fichier_in = NULL;
	FILE* fichier_out = NULL;

	fichier_in = fopen(nom_fichier, "r");
	if(fichier_in != NULL)
	{
		char str[MAX_SIZE];
		fgets(str, MAX_SIZE, fichier_in);
		mpz_set_str(c, str, BASE);
	}
	
	mpz_mul(n,p,q);
	cmp=mpz_cmp(n,c);
	if(!(cmp>0)) // si m n'est pas entre 0 et n-1
		printf("Error : message representative out of range\n");
	else
	{
		mpz_powm(m1,c,dP,p);
		mpz_powm(m2,c,dQ,q);
		mpz_sub(h,m1,m2);
		mpz_mul(h,h,Qinv);
		mpz_mod(h,h,p);
		mpz_mul(h,q,h);
		mpz_add(m,m2,h);
		
		fichier_out = fopen("keyoutdec.dat", "w");
		if(fichier_out != NULL)
		{
			gmp_fprintf(fichier_out,"%032Zx\n",m);			
			/*char * _m = mpz_get_str(NULL, BASE_IN, m);			
			fputs(_m, fichier_out);
			free(_m);*/
		}		

		//gmp_printf("message déchiffré = %Zd\n",m);
	}
	fclose(fichier_in);
	fclose(fichier_out);
	mpz_clear(c);
	mpz_clear(n);
	mpz_clear(m);
	mpz_clear(m1);
	mpz_clear(m2);
	mpz_clear(h);
} 


// génération d'une clé aléatoire de 128 bits pour le chiffrement AES //
void generate_sessionkey(int nbits,mpz_t k)
{
	/* initialisation de la graine pour la génération des nombres aléatoires */
	gmp_randstate_t state;
	gmp_randinit_default (state);
	gmp_randseed_ui (state, (unsigned) time(NULL));	

	mpz_urandomb(k,state,nbits);

	

	gmp_randclear(state);
}

void print_session(mpz_t k)
{
	FILE* fichier_sess  = NULL;
	fichier_sess = fopen("session_key.dat", "w");	

	if (fichier_sess != NULL)
	{
		//gmp_printf("clé de session = %032Zx\n",k);		
		gmp_fprintf(fichier_sess,"%032Zx\n",k);			
	}
	fclose(fichier_sess);
}

////////////////////////////////////////////////////////////////////////////

void generate_RSAkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv)
{
		
	/* initialisation de la graine pour la génération des nombres aléatoires */
	gmp_randstate_t state;
	gmp_randinit_default (state);
	gmp_randseed_ui (state, (unsigned) time(NULL));	

	mpz_t t,t1,t2,phi;
	mpz_inits(t,t1,t2,phi,NULL);		
	
	do
	{
		mpz_urandomb(p,state,nbits/2);
	} while(mpz_probab_prime_p(p,5)<=0);

	do
	{
		mpz_urandomb(q,state,nbits/2);
	} while(mpz_probab_prime_p(q,5)<=0);		
	
	if(mpz_cmp(q,p)>0)	
		mpz_swap(p,q); /* q shall be smaller than p (for calc of Qinv)*/		
	

	
	mpz_sub_ui(t1,p,1);
	mpz_sub_ui(t2,q,1);
	mpz_mul(phi,t1,t2);
	
	mpz_set_ui(e,65537);
	
	while( mpz_gcd_ui(t,phi,mpz_get_ui(e))!=1 ) // (while gcd is not 1) 
    	mpz_add_ui(e,e,2);

	mpz_invert(d,e,phi);  //inverse de e mod phi
	mpz_invert(Qinv,q,p); //inverse de q mod p
	mpz_invert(dP,e,t1);  //inverse de e mod p-1
	mpz_invert(dQ,e,t2);  //inverse de e mod q-1

	mpz_mul(n,p,q);
		
	// debug 
	//gmp_printf("e=%Zd\n\np=%Zd\n\nq=%Zd\n\nphi=%Zd\n\nn=%Zd\n\nQinv=%Zd\n\ndP=%Zd\n\ndQ=%Zd\n",e,p,q,phi,n,Qinv,dP,dQ); 
	
	mpz_clear(t);
	mpz_clear(t1);
	mpz_clear(t2);
	mpz_clear(phi);
	gmp_randclear(state);
}


/* keyID : identifiant sur 4 octets. ln, lm et lc : taille des chaines nom, mail et comment sur 1 octets */ 
void print_userid(int argc, char *argv[],mpz_t keyID,int ln,int lm, int lc, char *nom,char *mail, char *comment)
{
	int i;
	
	FILE* fichier_pub  = NULL;
	if(argc>2)	
		fichier_pub = fopen(argv[2], "w");	
	
	
	if (fichier_pub != NULL)
	{
		gmp_fprintf(fichier_pub,"%08Zx",keyID);	
		fprintf(fichier_pub,"%02x%02x%02x",ln,lm,lc);	
		for(i=0;i<ln;i++)
			fprintf(fichier_pub,"%x",nom[i]);
		for(i=0;i<lm;i++)
			fprintf(fichier_pub,"%x",mail[i]);	
		for(i=0;i<lc;i++)
			fprintf(fichier_pub,"%x",comment[i]);		
	}
	fclose(fichier_pub);
}



void print_pubkey(int argc, char *argv[],int year,int mon,int day,int nbits,mpz_t n,mpz_t e)
{
	FILE* fichier_pub  = NULL;
	if(argc>2)	
		fichier_pub = fopen(argv[2], "a");
	
	if (fichier_pub != NULL)
	{
		fprintf(fichier_pub,"%02x%04x%02x%02x%02x",04,year,mon,day,07); //04 version, 07 numero algo RSA1024.
		gmp_fprintf(fichier_pub,"%0256Zx",n);
		gmp_fprintf(fichier_pub,"%06Zx",e);  		
	}
	fclose(fichier_pub);
}


void get_pubkey(int argc, char *argv[],int nbits,mpz_t n,mpz_t e)
{
	//del_armureGPG(argv[1], "temp.dat"); // a utiliser lorqu'on utilise directement la clé pub et non le trousseau
	convertfile_b64tobin("temp.dat","temp2.dat");
	convertfile_bintohex("temp2.dat","clé.dat");
	remove("temp.dat");
	remove("temp2.dat");	
	
	FILE* fichier_pub  = NULL;
	fichier_pub = fopen("clé.dat", "r");	
	int t1,t2,t3;
	int v,y,m,d,a;
	char chaine[5];	

	if (fichier_pub != NULL)
	{
		char str[MAX_SIZE] ;

		fseek(fichier_pub, 8, SEEK_SET);
		fscanf(fichier_pub, "%2x %2x %2x", &t1,&t2,&t3);
		fseek(fichier_pub, 2*(t1+t2+t3)+0, SEEK_CUR); //+12 ??
		
		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", &v);

		fgets(chaine, 5, fichier_pub);		
		sscanf(chaine, "%04X", &y);

		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", &m);

		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", &d);

		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", &a);

		//printf("version : %d, %d-%d-%d, algo : %d\n",v,y,m,d,a);
		
		//get n sur 256 bytes
		fgets(str, 256+1, fichier_pub); 
  		mpz_set_str(n, str, BASE);
		
		//get e sur 6 bytes
		fgets(str, 6+1, fichier_pub);
  		mpz_set_str(e, str, BASE);
  	}
	//remove("clé.dat");
	fclose(fichier_pub);
}



void get_pubkeyring(int argc, char *argv[],int nbits,mpz_t n,mpz_t e)
{
	FILE *f=NULL;
	FILE *pubkey=NULL;
		
	f=fopen("pubring.dat","r");
	pubkey=fopen("temp.dat","w");

	char chaine[MSG_SIZE];
	char *c=NULL;
	
		
	while(fgets(chaine,MSG_SIZE,f) != NULL )
	{		
		c=strstr(chaine, argv[2]);		
		if(c!=NULL)
			break;
	}
	fgets(chaine,MSG_SIZE,f);		
	fgets(chaine,MSG_SIZE,f);
	fgets(chaine,MSG_SIZE,f);
	fgets(chaine,MSG_SIZE,f);
	fscanf(f,"%s",chaine);
	fprintf(pubkey,"%s",chaine);
	fclose(f);
	fclose(pubkey);
	get_pubkey(argc,argv,nbits,n,e);
	/*gmp_printf("n =%0256ZX\n",n);
	gmp_printf("e =%06ZX\n",e);	*/
		
}	



void print_privkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv)
{
	FILE* fichier_priv  = NULL;
	fichier_priv = fopen("priv_key.dat", "w");	


	if (fichier_priv != NULL)
	{
		gmp_fprintf(fichier_priv,"%0256Zx\n",n);
		gmp_fprintf(fichier_priv,"%06Zx\n",e);  
		gmp_fprintf(fichier_priv,"%0256Zx\n",d);
		gmp_fprintf(fichier_priv,"%06Zx\n",p); 
		gmp_fprintf(fichier_priv,"%0128Zx\n",q);
		gmp_fprintf(fichier_priv,"%0128Zx\n",dP); 
		gmp_fprintf(fichier_priv,"%0128Zx\n",dQ);
		gmp_fprintf(fichier_priv,"%0128Zx\n",Qinv); 		
	
	}
	fclose(fichier_priv);
	
}

void get_privkey(int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv)
{
	FILE* fichier_priv  = NULL;
	fichier_priv = fopen("priv_key.dat", "r");	

	if (fichier_priv != NULL)
	{
		char str[MAX_SIZE] ;
		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(n, str, BASE);
  		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(e, str, BASE);
		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(d, str, BASE);
  		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(p, str, BASE);
		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(q, str, BASE);
  		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(dP, str, BASE);
		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(dQ, str, BASE);
  		fgets(str, MAX_SIZE, fichier_priv);
  		mpz_set_str(Qinv, str, BASE);
  	}
	fclose(fichier_priv);
	remove("priv_key.dat");
}

void get_privkeyring(int argc, char *argv[],int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv)
{
	FILE *f=NULL;
	FILE *privkey=NULL;
		
	f=fopen("secring.dat","r");
	privkey=fopen("priv_key.dat","w");
	
	int i=0;
	char chaine[MSG_SIZE];
	char *c=NULL;
	
		
	while(fgets(chaine,MSG_SIZE,f) != NULL )
	{		
		c=strstr(chaine, argv[2]);		
		if(c!=NULL)
			break;		
	}
	for(i=0;i<8;i++)
	{	
		fgets(chaine,MSG_SIZE,f);
		fscanf(f,"%s",chaine);
		fprintf(privkey,"%s\n",chaine);
	}	

	fclose(f);
	fclose(privkey);
	get_privkey(nbits,n,e,d,p,q,dP,dQ,Qinv);

	/*gmp_printf("dP =%0128ZX\n",dP);
	gmp_printf("dQ =%0128ZX\n",dQ);	*/
		
}	


