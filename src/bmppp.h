#ifndef BMPPP_H
#define BMPPP_H



typedef struct{int R ; int G ; int B;} pixel ;
unsigned int writeBMP(FILE* f , long int width , long int height ,pixel* p);
void* readBMP(FILE* f , long int* width , long int* height);
pixel* init(unsigned long long int size);






#endif //end of header file
