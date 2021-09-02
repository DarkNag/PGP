#ifndef DEF_CONVERSION
#define DEF_CONVERSION

#define MSG_SIZE 10000

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b16[] = "0123456789abcdef";

void fprint_bin(int deci,int nb,FILE *fichier);
void print_bin(int deci,int nb);
void fprint_hex(char *hex,int nb,FILE *fichier); //nb=4
void fprint_b64(char *hex,int nb,FILE *fichier); //nb=6
void convertfile_asciitohex(char *nomfichier_in, char *nomfichier_out);
void convertfile_hextoascii(char *nomfichier_in, char *nomfichier_out);
void convertfile_hextobin(char *nomfichier_in, char *nomfichier_out);
void convertfile_bintohex(char *nomfichier_in, char *nomfichier_out);
void convertfile_bintob64(char *nomfichier_in, char *nomfichier_out);
static unsigned val (char c);
void convertfile_b64tobin(char *nomfichier_in, char *nomfichier_out);
void make_armureGPG(int version, char *nomfichier_in, char *nomfichier_out);
void del_armureGPG(char *nomfichier_in, char *nomfichier_out);


#endif 
