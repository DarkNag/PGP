#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>

#include "include/Constantes.h"
#include "include/aes.h"
#include "include/rsa.h"
#include "include/conversion.h" 



void my_options(int argc, char **argv)
{
    int     i;
    size_t  j;

    for (i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-')
            for (j = 1; argv[i][j] != '\0'; ++j)
            	tab[(size_t)(unsigned char)argv[i][j]] = 1;
    }
}


static void purger(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
    {}
}

static void clean (char *chaine)
{
    char *p = strchr(chaine, '\n');
    if (p)
    {
        *p = 0;
    }
    else
    {
        purger();
    }
}

void print_paquetkey(char *nomfichier,mpz_t keyID)
{
	FILE* fichier  = NULL;
	fichier = fopen(nomfichier, "w+");	
	
	if (fichier != NULL)
	{
		gmp_fprintf(fichier,"%08Zx",keyID);
	}
	fclose(fichier);
}

void genrate_GPGkey(int argc, char *argv[],int nbits,mpz_t n,mpz_t e,mpz_t d,mpz_t p,mpz_t q,mpz_t dP,mpz_t dQ,mpz_t Qinv,mpz_t keyID)
{
	char nom[100]="";
	char mail[100]="";
	char comment[100]="";

	mpz_t masque;
	mpz_init(masque);
	mpz_set_str(masque, "ffffffff", 16);

	int choix;
	int c=0;
	int year,mon,day;
	date(&year,&mon,&day);	

	printf("Sélectionnez le type de clef désiré :\n"
			"   (1) RSA\n"
			"Quel est votre choix ? ");
	scanf("%d",&choix);
	printf("\n");	
	
	if(choix==1)
	{
		printf( "Une identité est nécessaire à la clef ; le programme la construit à partir   \n"
				"du nom réel, d'un commentaire et d'une adresse électronique de cette façon : \n"
				"   « Heinrich Heine (le poète) <heinrichh@duesseldorf.de> »\n");
		do{
		printf("\n");			
		fgetc(stdin);
		printf("Nom réel : ");
		fgets(nom, sizeof(nom), stdin);
		clean(nom);
		printf("Adresse électronique : ");
		fgets(mail, sizeof(mail), stdin); 
		clean(mail);
		printf("Commentaire : ");
		fgets(comment, sizeof(comment), stdin);
		clean(comment);		
		
		if(strlen(comment)==0)
			printf("Vous avez sélectionné cette identité :\n"
					"« %s <%s> »\n",nom,mail);
		else
			printf("Vous avez sélectionné cette identité :\n"
					"« %s (%s) <%s> »\n",nom,comment,mail);


		printf("Faut-il la modifier ? (0) Oui/ (1) Non ");
		scanf("%d",&c);
		}while(c!=1);

		generate_RSAkey(nbits,n,e,d,p,q,dP,dQ,Qinv);
		mpz_and(keyID,n,masque); //obtention de UserID
			
		print_userid(argc,argv,keyID,(int)strlen(nom),(int)strlen(mail),(int)strlen(comment),nom,mail,comment);
		print_pubkey(argc,argv,year,mon,day,nbits,n,e);
	
		convertfile_hextobin(argv[2],"temp.dat");
		convertfile_bintob64("temp.dat","temp2.dat");
		make_armureGPG(1,"temp2.dat", argv[2]);
		remove("temp.dat");
		remove("temp2.dat");
		

		print_privkey(nbits,n,e,d,p,q,dP,dQ,Qinv);

		printf("\n\n");
						
			
		gmp_printf("la clé %08ZX est générée avec succés\n",keyID);
		printf("les clefs publique et secrète ont été créées\n\n"); 

		gmp_printf("pub 1024R/%08ZX ",keyID);
		printf("%04d-%02d-%02d\n",year,mon,day);
		printf("uid\t\t   %s (%s) <%s>\n",nom,comment,mail);

		printf("Voulez vous ajouter la clé à votre trousseau de clés ? (0) Oui/ (1) Non \n"); 
		scanf("%d",&c);
		if(c==0)
		{
			FILE *pubring=NULL; FILE *secring=NULL;
			FILE *pubkey=NULL;  FILE *seckey=NULL;

			pubring = fopen("pubring.dat","a");
			secring = fopen("secring.dat","a");	
			pubkey=fopen(argv[2],"r");
			seckey=fopen("priv_key.dat","r");			
					
			if(pubring != NULL & pubkey != NULL & secring !=NULL & seckey !=NULL)
			{
				int car;
				char chaine[MSG_SIZE];				
				fputc('\n', pubring); fputc('\n', secring);
				fputc('\n', pubring); fputc('\n', secring);
				gmp_fprintf(pubring,"pub 1024R/%08ZX ",keyID);
				gmp_fprintf(secring,"pub 1024R/%08ZX ",keyID);
				fprintf(pubring,"%04d-%02d-%02d\n",year,mon,day);
				fprintf(secring,"%04d-%02d-%02d\n",year,mon,day);
				fprintf(pubring,"uid\t\t\t\t   %s (%s) <%s>\n",nom,comment,mail);
				fprintf(secring,"uid\t\t\t\t   %s (%s) <%s>\n",nom,comment,mail);
				while(fgets(chaine, MSG_SIZE, pubkey) != NULL)
				{
					fprintf(pubring,"%s",chaine);
				}
				while(fgets(chaine, MSG_SIZE, seckey) != NULL)
				{
					fprintf(secring,"%s",chaine);
				}
			}
			fclose(pubring); fclose(secring);
			fclose(pubkey); fclose(seckey);
			printf("La clé a été ajouté au trousseau de clés avec succès\n\n"); 
			remove("priv_key.dat");
		}

		mpz_clear(masque);
	}
}

void get_info(char *nomfichier_keypub,long *keyid,int *y,int *m,int *d,int *v1,int *v2,int *v3,char *nom, char *mail, char *comment)
{
	del_armureGPG(nomfichier_keypub, "temp.dat"); 
	convertfile_b64tobin("temp.dat","temp2.dat");
	convertfile_bintohex("temp2.dat","clé.dat");
	remove("temp.dat");
	remove("temp2.dat");

	FILE* fichier_pub  = NULL;
	fichier_pub = fopen("clé.dat", "r");	
	
	int t1,t2,t3;
	char chaine[100];	

	if (fichier_pub != NULL)
	{
		fgets(chaine, 9, fichier_pub);		
		sscanf(chaine, "%08lX", keyid);
		
		fscanf(fichier_pub, "%2x %2x %2x", &t1,&t2,&t3);

//		printf("%d %d %d\n",t1,t2,t3);

		fgets(nom, 2*t1+1, fichier_pub);
		fgets(mail, 2*t2+1, fichier_pub);
		fgets(comment, 2*t3+1, fichier_pub);
   			
		fgets(chaine, 3, fichier_pub);		
	
		fgets(chaine, 5, fichier_pub);		
		sscanf(chaine, "%04X", y);

		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", m);

		fgets(chaine, 3, fichier_pub);		
		sscanf(chaine, "%02X", d);
		
		*v1=t1;
		*v2=t2;	
		*v3=t3;
  	}
	//remove("clé.dat");
	fclose(fichier_pub);
}




void add_tousseau(char *nomfichier_keypub)
{
	FILE *pubring=NULL; 
	FILE *pubkey=NULL;  

	long keyid;
	int v1,v2,v3,y,m,d;	
	char nom[100];
	char mail[100];
	char comment[100];

	get_info(nomfichier_keypub,&keyid,&y,&m,&d,&v1,&v2,&v3,nom,mail,comment);
	printf("%d  %d  %d\n",v1,v2,v3);	
	printf("%04lx\n",keyid);	
	printf("%04x-%02x-%02x\n",y,m,d);
	printf("%s\n",nom);
	printf("%s\n",mail);
	printf("%s\n",comment);

	printf("pub 1024R/%04lX ",keyid);
	printf("%04d-%02d-%02d\n",y,m,d);
	printf("uid\t\t   %s (%s) <%s>\n",nom,comment,mail);

	pubring = fopen("pubring.dat","a");
	pubkey=fopen(nomfichier_keypub,"r");
	

	if(pubring != NULL & pubkey != NULL)
	{
		int car,i,c;
		char chaine[MSG_SIZE];				
		fputc('\n', pubring); 
		fputc('\n', pubring); 
		fprintf(pubring,"pub 1024R/%04lX ",keyid);
		fprintf(pubring,"%04d-%02d-%02d\n",y,m,d);
		fprintf(pubring,"uid\t\t\t\t  "); 
		for(i=0;i<v1;i++)		
		{			
			//fgets(chaine,3,nom);			
			sscanf(nom, "%02X", &c);	
			fprintf(pubring,"%c",c);		
		}
		fputs(" (",pubring);	
		for(i=0;i<v3;i++)		
		{			
			sscanf(comment, "%02X", &c);	
			fprintf(pubring,"%c",c);		
		}
		fputs(") <",pubring);
		for(i=0;i<v2;i++)		
		{			
			sscanf(mail, "%02X", &c);	
			fprintf(pubring,"%c",c);		
		}
		fputs("> \n",pubring);

		while(fgets(chaine, MSG_SIZE, pubkey) != NULL)
		{
			fprintf(pubring,"%s",chaine);
		}
	}
	fclose(pubring); 
	fclose(pubkey); 
	printf("La clé a été ajouté au trousseau de clés publiques avec succès\n\n"); 

}

void longueur(char *nomfichier_in)
{
	FILE *fichier_in;
	FILE *fichier_out;
	int t=0;
	fichier_in=fopen(nomfichier_in,"r");
		
	if(fichier_in!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);
		printf("longueur =%d\n",t);
		rewind(fichier_in);
		
	}
	fclose(fichier_in);

}




int main(int argc, char *argv[])
{
	int nbits = 1024;
	mpz_t n,e,d,p,q,dP,dQ,Qinv,keyID,k;
	mpz_inits(n,e,d,p,q,dP,dQ,Qinv,keyID,k,NULL);
	
	byte in[4*Nb]={0};
	byte out[4*Nb]={0};
	byte key[4*Nk]={0};
	word w[Nb*(Nr+1)]={0};

	my_options(argc,argv);	

	if((tab[(size_t)(unsigned char)'h']) || (argc==1))
	{
		printf( "\n"
				"NAME\nPGP - Pretty Good Privacy\n\n"
				"SYNOPSIS\naes Input_File Key_File [-d]\naes [-h]\n\n"
				"DESCRIPTION\nEncrypt and decrypt text using A.E.S\n"
				"if '-d' is not precised, aes is encryption mode.\n\n"
				"Input_File : file exist, reading access\n"
				"Key_File   : file exist, reading access and contains the A.E.S key\n"
				"-d         : decryption mode\n"
				"-h         : print help and exit\n\n"
				"AUTHOR\nThomas VASSEUR <thomas.vasseur@etudiant.univ-rennes1.fr>\n\n" 
				"VERSION\n0.99 (26/04/2013)\n\n");
		return 0;
	}		

	else if(tab[(size_t)(unsigned char)'g'])
	{
		genrate_GPGkey(argc,argv,nbits,n,e,d,p,q,dP,dQ,Qinv,keyID);
	}
	else if(tab[(size_t)(unsigned char)'a'])
	{
		add_tousseau(argv[2]);
	}	
	else if(tab[(size_t)(unsigned char)'c'])
	{
		FILE *messagegpg = NULL;
		FILE *sessionkey = NULL;
		FILE *cipherfile = NULL;
		
		char chaine[MSG_SIZE];	
			
		get_pubkeyring(argc,argv,nbits,n,e);
		//gmp_printf("n=%06Zx\n",n);			
		//gmp_printf("e=%06Zx\n",e);		
		generate_sessionkey(128,k);
		print_session(k);
		chiffrerRSA(n,e,"session_key.dat"); //creation du fichier keyout.dat
		
		//AES		
		etendre_cle("session_key.dat",key,w);
		convertfile_asciitohex(argv[3],"message.dat");	
		aes_encrypt("message.dat","temp.dat",in,out,w);
		remove("message.dat");
		//AES

		messagegpg = fopen("clé.dat","a");
		sessionkey = fopen("keyout.dat","r");
		cipherfile = fopen("temp.dat","r");

		if(messagegpg != NULL & sessionkey != NULL)
		{
			fgets(chaine,256+1,sessionkey);
			fprintf(messagegpg,"%s",chaine);
			fgets(chaine,MSG_SIZE,cipherfile);
			fprintf(messagegpg,"%s",chaine);
		}
		fclose(messagegpg);
		fclose(sessionkey);
		fclose(cipherfile);

		remove("session_key.dat");
		remove("keyout.dat");	
		remove("temp.dat");

		convertfile_hextobin("clé.dat","temp.dat");
		convertfile_bintob64("temp.dat","clé.dat");
		make_armureGPG(2,"clé.dat", argv[3]);
		remove("clé.dat");
		remove("temp.dat");

		printf("Chiffrement du message réussi : %s\n",argv[3]);
		

		
	}	
	else if(tab[(size_t)(unsigned char)'d'])
	{
		FILE *messagegpg = NULL;
		FILE *sessionkey = NULL;	
		FILE *cipherfile = NULL;
		
		char chaine[MSG_SIZE];	
		int v1,v2;
		int t1,t2,t3;
		
		get_privkeyring(argc,argv,nbits,n,e,d,p,q,dP,dQ,Qinv);
		//gmp_printf("e=%Zx\n",e);
		del_armureGPG(argv[3],"temp.dat");
		convertfile_b64tobin("temp.dat","temp2.dat");
		convertfile_bintohex("temp2.dat","temp.dat");

		remove("temp2.dat");

		messagegpg = fopen("temp.dat","r");	
		sessionkey = fopen("session_key.dat","w");
		cipherfile = fopen("textechiffre.dat","w");
		
		if(messagegpg != NULL && sessionkey!= NULL && cipherfile != NULL)
		{
			sscanf(argv[2],"%X", &v1);
			fgets(chaine, 9, messagegpg);
			sscanf(chaine, "%X", &v2);
					
			if(v1==v2)
			{
				fscanf(messagegpg, "%2x %2x %2x", &t1,&t2,&t3);
				//printf("%d %d %d\n",t1,t2,t3);
				fseek(messagegpg, 2*(t1+t2+t3)+12+256+6, SEEK_CUR);	
				//on recupere la clé chiffré				
				fgets(chaine, 256+1, messagegpg);
				fprintf(sessionkey,"%s",chaine);
				//on recupere le msg chiffré				
				fgets(chaine, MSG_SIZE, messagegpg);
				fprintf(cipherfile,"%s",chaine);
				
				fclose(sessionkey);
				fclose(cipherfile);
				fclose(messagegpg);

				remove("temp.dat");

				dechiffrerRSA(p,q,dP,dQ,Qinv,"session_key.dat"); //creation du fichier keyoutdec.dat
				remove("session_key.dat");	
							

				//AES		
				etendre_cle("keyoutdec.dat",key,w);
				aes_decrypt("textechiffre.dat","temp.dat",in,out,w);
				convertfile_hextoascii("temp.dat","cipher.dat");
				//AES
				
				remove("keyoutdec.dat");
				remove("temp.dat");
				remove("textechiffre.dat");

				printf("Déchiffrement du message réussi : cipher.dat\n");
				
			}	
			else
			{
				printf("Error: le message a été chiffré avec la clé publique de l'utilisateur : %08X\n",v2);
				printf("Déchiffrement du message impossible\n");
			}
			
			//printf("%x\n",valeur);
			//gmp_printf("%Zx",n);
		}

		

		
		//dechiffrerRSA(p,q,dP,dQ,Qinv,"keyout.dat");
		/*aes_decrypt(in,out,w);
		convertfile_hextoascii("plain_file.dat","message.dat");	*/
	}


	mpz_clear(n);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(dP);
	mpz_clear(dQ);
	mpz_clear(Qinv);
	mpz_clear(keyID);
	mpz_clear(k);

	return 0;
}
