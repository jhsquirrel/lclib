#ifndef endian_funcs_h
#define endian_funcs_h
#define UWORD_32bits  unsigned long
#define UWORD_16bits  unsigned short
#define UBYTE_08bits  unsigned char
UWORD_32bits convert_to_32(unsigned char str[4]){
        UWORD_32bits R = 0x00000000;
#ifdef BIG_ENDIAN        
        R = str[3];
        R = R << 8;
        R += str[2];
        R = R << 8;
        R += str[1];
        R = R << 8;
        R += str[0];
#endif
#ifdef LE
	R = str[0];
        R = R << 8;
        R += str[1];
        R = R << 8;
        R += str[2];
        R = R << 8;
        R += str[3];
#endif
        return R;
}

char convert_from_32(UWORD_32bits X,int bit){
        char c=0;

#ifdef BIG_ENDIAN    
        switch(bit){
        case 0:
                c = (char) (X & 255);
                break;
        case 1:
                c = (char) ((X >> 8) & 255);
                break;
        case 2:
                c = (char) ((X >> 16) & 255);
                break;
        case 3:
                c = (char) ((X >> 24) & 255);
                break;
	}
#endif
#ifdef LE
	switch(bit){
	case 0:
                c = (char) ((X >>24) & 255);
                break;
        case 1:
                c = (char) ((X >> 16) & 255);
                break;
        case 2:
                c = (char) ((X >> 8) & 255);
                break;
        case 3 :
                c = (char) (X & 255);
                break;
        }
#endif
        return c;
}
#endif
