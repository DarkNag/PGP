#ifndef DEF_AES
#define DEF_AES

void AddRoundKey(state s,state k);
void State(state s, byte b[4*Nb]);
void Block(state s, byte b[4*Nb]);
byte mult(byte a1, byte a2);
byte multX(byte a);
void affiche_state(state s);
void affiche_block(byte b[4*Nb]);

void Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);
void SubBytes(state s);
void ShiftRows(state s);
void MixColumns(state s);
void mixcolumn(word w, word w1);

void InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);
void InvSubBytes(state s);
void InvShiftRows(state s);
void InvMixColumns(state s);
void invmixcolumn(word w, word w1);

void KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)]);
void RotWord(word w);
void SubWord(word w);

void print_state(byte b[4*Nb],FILE *fichier);
void etendre_cle(char *nomfichier,byte key[4*Nk], word w[Nb*(Nr+1)]);
void aes_encrypt(char *nomfichier_in, char *nomfichier_out, byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);
void aes_decrypt(char *nomfichier_in, char *nomfichier_out, byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)]);


#endif
