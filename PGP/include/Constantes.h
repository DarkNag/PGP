#ifndef DEF_CONSTANTES
#define DEF_CONSTANTES

#define Nb 4
#define Nk 4
#define Nr 10

typedef unsigned char byte; //byte est un unisgned char.
typedef byte word[Nb];      //word est un tableau de 4 byte.
typedef word state[Nb];     //state est un tableau de 4 word.

static char tab[1 << (sizeof(char) << 3)] = {0}; 

// S-Box 
extern const byte Sbox[256];

// Inv S-box 
extern const byte InvSbox[256];
 
// Rcon 
extern const word Rcon[11]; 

#endif
