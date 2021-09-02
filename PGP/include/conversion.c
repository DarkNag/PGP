#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "conversion.h"

//static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//static const char b16[] = "0123456789abcdef";

void fprint_bin(int deci,int nb,FILE *fichier)
{
	int i,bin=0;
	for(i=nb-1;i>=0;i--)
	{
		bin=((unsigned)deci>>i)&0x01;
		fprintf(fichier,"%d",bin);
	}
	//printf("\n");
}

/////////////////////////////////////////////////
void print_bin(int deci,int nb)
{
	int i,bin=0;
	for(i=nb-1;i>=0;i--)
	{
		bin=((unsigned)deci>>i)&0x01;
		printf("%d",bin);
	}
	printf("\n");
}
/////////////////////////////////////////////////


void fprint_hex(char *hex,int nb,FILE *fichier) //nb=4
{
	int i,bin=0;
	int puissance[4] = {8,4,2,1};
	for(i=0;i<nb;i++)
		bin+=((int)(hex[i]-'0'))*puissance[i];
	fprintf(fichier,"%c",b16[bin]);
}

void fprint_b64(char *hex,int nb,FILE *fichier) //nb=6
{
	int i,bin=0;
	int puissance[6] = {32,16,8,4,2,1};
	for(i=0;i<nb;i++)
		bin+=((int)(hex[i]-'0'))*puissance[i];
	fprintf(fichier,"%c",b64[bin]);
}

void convertfile_asciitohex(char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;
	
	int caractere; 	
	long t,i;

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");

	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in)-1;
		rewind(fichier_in);
		i=0;		
		do
		{
			caractere=fgetc(fichier_in);
			fprintf(fichier_out,"%2x",caractere);
			i++;   
		}while (caractere != EOF && i<t);
	}
	fclose(fichier_in);
	fclose(fichier_out);
}


void convertfile_hextoascii(char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;
	
	char chaine[3] = ""; 
	int valeurBin;
	long t,i;	

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");

	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);
		rewind(fichier_in);
		//printf("%ld\n",t);		
		i=0;		
		while (fgets(chaine, 3, fichier_in) != NULL && i<(t/2))
		{
			sscanf(chaine, "%2X", &valeurBin) ;			
			fprintf(fichier_out,"%c",valeurBin);   
			i++;		
		}
	}
	fclose(fichier_in);
	fclose(fichier_out);

	
}


void convertfile_hextobin(char *nomfichier_in, char *nomfichier_out)
{	
	FILE *fichier_in;
	FILE *fichier_out;
	
	char chaine[3] = "";	
	int valeurBin;
	int t,i;

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");

	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);//-1;
		rewind(fichier_in);
		i=0;	
		while (fgets(chaine, 3, fichier_in) != NULL && i<(t/2))
		{
			sscanf(chaine, "%2X", &valeurBin) ;
			fprint_bin(valeurBin,8,fichier_out);   
			i++;    	
		}
	}	
	fclose(fichier_in);
	fclose(fichier_out);	

}

void convertfile_bintohex(char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;

	char chaine[5] = "";
	int t,i;

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");
	
	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);
		rewind(fichier_in);
		i=0;			
		while (fgets(chaine, 5, fichier_in) != NULL && i<(t/4))
		{
			fprint_hex(chaine,4,fichier_out);
			i++;
		}
	}
	fclose(fichier_in);
	fclose(fichier_out);
}


void convertfile_bintob64(char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;

	char chaine[7] = "";
	int test,t,i;

	fichier_in=fopen(nomfichier_in,"r+");
	fichier_out=fopen(nomfichier_out,"w");
	
	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);
		test=t-(t/6)*6;
		if(test==4)
			fputs("00",fichier_in);
		else if(test==2)
			fputs("0000",fichier_in);
		rewind(fichier_in);

		i=0;			
		while (fgets(chaine, 7, fichier_in) != NULL && i<=(t/6))
		{
			fprint_b64(chaine,6,fichier_out);
			i++;
		}
	
	if(test==4)
		fputs("=",fichier_out);
	else if(test==2)
		fputs("==",fichier_out);
	}
	fclose(fichier_in);
	fclose(fichier_out);
}

static unsigned val (char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    else if (c >= 'a' && c <= 'z')
        return 26 + c - 'a';
    else if (c >= '0' && c <= '9')
        return 52 + c - '0';
    else if (c == '+')
        return 62;
    else if (c == '/')
        return 63;
    else
        return -1;
}

void convertfile_b64tobin(char *nomfichier_in, char *nomfichier_out)
{	
	FILE *fichier_in;
	FILE *fichier_out;
	
	int caractere;	
	int valeurBin;
	int eg,t,i; //la variable "eg" contient le nombre de '=' à la fin du fichier
	eg=0;

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");

	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		fseek(fichier_in,0,SEEK_END);
		t=(int) ftell(fichier_in);
		
		//calcul du nombre de '='
		fseek(fichier_in, -1, SEEK_CUR);
		caractere=fgetc(fichier_in);
		if(val(caractere)==-1)
		{
			eg++;
			fseek(fichier_in, -2, SEEK_CUR);
			caractere=fgetc(fichier_in);
			if(val(caractere)==-1)
				eg++;
		}
		//printf("%d\n",eg);
		
		rewind(fichier_in);
		i=0;	
		do
		{
			caractere=fgetc(fichier_in);
			fprint_bin(val(caractere),6,fichier_out);   
			i++;    	
		}while (caractere != EOF && i<(t-eg-1));
		//traitement particulier pour les derniers bits
		caractere=fgetc(fichier_in);
		if(eg==2)
			{
				fputc((val(caractere))&(1<<5)?'1':'0',fichier_out);
				fputc((val(caractere))&(1<<4)?'1':'0',fichier_out);
			}		
		else if(eg==1)	
			{
				fputc((val(caractere))&(1<<5)?'1':'0',fichier_out);
				fputc((val(caractere))&(1<<4)?'1':'0',fichier_out);
				fputc((val(caractere))&(1<<3)?'1':'0',fichier_out);
				fputc((val(caractere))&(1<<2)?'1':'0',fichier_out);
			}
		else
			fprint_bin(val(caractere),6,fichier_out); 	
	}	
	fclose(fichier_in);
	fclose(fichier_out);	

}

void make_armureGPG(int version, char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;

	char chaine[MSG_SIZE];

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");
	
	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		if(version==1)		
			fputs("----- BEGIN PGP KEY BLOCK-----\n",fichier_out);
		else if(version==2)
			fputs("----- BEGIN PGP MESSAGE-----\n",fichier_out);		
		fputs("Version 0.99\n\n",fichier_out);				
		while (fgets(chaine, MSG_SIZE, fichier_in) != NULL) 
        {
            fprintf(fichier_out,"%s", chaine); 
        }
		if(version==1)		
			fputs("\n----- END PGP KEY BLOCK-----",fichier_out);	
		else if(version==2)		
			fputs("\n----- END PGP MESSAGE-----",fichier_out);
	}
	fclose(fichier_in);
	fclose(fichier_out);
}

void del_armureGPG(char *nomfichier_in, char *nomfichier_out)
{
	FILE *fichier_in;
	FILE *fichier_out;

	char chaine[MSG_SIZE];
	char c;

	fichier_in=fopen(nomfichier_in,"r");
	fichier_out=fopen(nomfichier_out,"w");
	
	if(fichier_in!=NULL && fichier_out!=NULL)
	{
		//on saute 3 lignes
		fgets(chaine, MSG_SIZE, fichier_in);
		fgets(chaine, MSG_SIZE, fichier_in);
		fgets(chaine, MSG_SIZE, fichier_in);	
 		fscanf(fichier_in,"%s",chaine);
		fprintf(fichier_out,"%s",chaine);
	}
	fclose(fichier_in);
	fclose(fichier_out);
}

