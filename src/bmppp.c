#include <stdio.h>
#include <stdlib.h>
/**BMP HEADER IS 14 BYTES LONG
 * First 2 bytes clarify the type 0x42 & 0x4D
 * Next 4 bytes contain the raw size HEADERS + _data
 * Next 4 bytes are reserved (set to 0)
 * Next 4 bytes contain the offset to _data
 * -------------DIB HEADER--------------------------
 * 0x0E contains the size of the DIB header
 * 0x12 contains the width of the bitmap
 * 0x16 contains the height of the bitmap
 * 0x1A contains the number of colour plains =1
 * 0x1C contains the number of bits per pixel = 24
 * 0x1E contains the compression method BI_RGB(none) = 0
 * 0x22 raw _data size , can be given 0 for BI_RGB
 * 0x26 & 0x2A contain the resolutions pixel/meter
 * 0x2E number of colours in the palette 0 to 2^n
 * 4byte allignment ROW = ((BITSPERPIXEL * WIDTH + 31 ) / 32 ) * 4
 * PixelArraySize = RowSize * Height
 * Pixel array starts from the lower left corner
 * Size of the HEADERS 54 bytes
 * Saved as BGR
 **/




typedef struct {int R ;int G ;int B;} pixel; //Structure to store pixel data

/** Returns the width if succesful
 *  Read the first 2 bytes to clarify the filetype
 *  0x12 and 0x16 , width & height respectively
 *  0x0A is the offset
**/
long int bytetoInt(unsigned char* ch){ return ((int)ch[3]<<24) |  ((int)ch[2]<<16) |((int)ch[1]<<8) | ((int)ch[0]);}

void* readBMP(FILE* f , unsigned long int* width ,unsigned long int* height){

	if(!f)return NULL; //is the file valid
 	
	char head[2]; //BM header
	char* _temp;  //temporary variable
	fread(head , sizeof(char)*2 , 1, f);

	if(!(head[0]<<8) + head[1]== 0x424D)return NULL; //Not a bmp file

	//Width & Height return it to the main func
	fseek( f , 0x12, SEEK_SET);
	_temp = malloc(sizeof(int));
	fread(_temp , sizeof(int) , 1 , f);
	*width = bytetoInt(_temp);
	fread(_temp , sizeof(int) , 1 , f);
	*height = bytetoInt(_temp);
	//Find the offset
	long int offset , size = (*height) * (*width);
	int padding = (4-((*width * 3)%4))%4 ;
	fseek( f , 0x0A , SEEK_SET);
	fread(_temp , sizeof(int) , 1 , f);
	offset = bytetoInt(_temp);
	
	//Read the data 
	fseek( f , offset , SEEK_SET);   //Jump to the start of the data


	pixel* temp_pix = calloc(size , sizeof(pixel));//Create a temporary array
	
	int i , _r  = 0; //counters _r is to determine the row ending/padding
	for(i = 0 ; i<size ; i++){
		
		fread(_temp , sizeof(char) , 1 , f);
		temp_pix[i].B = bytetoInt(_temp);
		fread(_temp , sizeof(char) , 1 , f);
		temp_pix[i].G = bytetoInt(_temp);
		fread(_temp , sizeof(char) , 1 , f);
		temp_pix[i].R = bytetoInt(_temp);
		
		
		_r++;
		if(_r == *width ) {
		
			fseek( f , padding , SEEK_CUR); //Padding
			_r = 0;
	
		}//End of if
	
		
	
	}
	
	



	return temp_pix;


}//End of read



/**Write Bmp function
 * Returns 0 if succesfull
 **/
unsigned int writeBMP(FILE* f ,long int width , long int height ,pixel* p){


	if(!f)return 1 ; //If f isn't initialized return 1



	//Setup / HEADERS

	const int _p = (4 - ((width * 3)%4 ))%4;//Amount of padding
	const int row_size = width * 3 + _p;//Rowsize
	const char padding_b = 0; 	    //Padding bytes 0 in this case
	const int pix_arr_size = row_size * height ;

	const int  BM = 0x4D42;
	const int _bmsize = 54 + pix_arr_size ;
	const int reserved =  0;

	const int offset = 0x36 ; //Offset where the pixel array can be found

	//DIB HEADER
	const int DIB_size  = 40 ;
	//WIDTH
	//HEIGHT
	const int colour_plane = 1;
	const int bit_size  = 0x18;
	const int bmp_comp = 0; //No compression
	//pix_arr_size
	const int res = 0x0B13; //
	  	  
	const int colour_pallete = 0; //Colour pallete null
	const int imp_colours    = 0; //Important colour (I have no idea what this is)

	
	//Write the header

 
	fwrite(&BM , sizeof(char) * 2, 1 , f ); //File type
	fwrite(&_bmsize , sizeof(int) , 1 , f ); //Raw file size 
	fwrite(&reserved  , sizeof(int) , 1 , f);       //Reserved int
	fwrite(&offset , sizeof(int) , 1 , f);	//Offset 
	fwrite(&DIB_size , sizeof(int) , 1 , f);	//DIB header size
	fwrite(&width , sizeof(int) , 1 , f);    //Width
	fwrite(&height , sizeof(int) , 1, f) ;   //Height
	fwrite(&colour_plane , sizeof(char) * 2 , 1 , f); //Colour plane
	fwrite(&bit_size , sizeof(char) * 2 , 1 , f); 	 //Bits per pixel
	fwrite(&bmp_comp , sizeof(int) , 1 , f);	//No compression
	fwrite(&pix_arr_size , sizeof(int) , 1 , f); 	//Raw bmp data size
	fwrite(&res , sizeof(int) , 1 , f); 	//Resolution sth ... 
	fwrite(&res , sizeof(int) , 1 , f);     //Resolution sth ...
	fwrite(&colour_pallete , sizeof(int) , 1 ,f); 	//No colour pallete 
	fwrite(&imp_colours , sizeof(int) , 1 , f);// all colours 
	
	int i , j ; //Counter setup

	for(i = 0 ; i < height ; i++){

		for(j = 0 ; j < width ; j++){

			if(!p)return 1; //Error
			
			if(p->R > 255)p->R = 255;
			if(p->G > 255)p->G = 255;
			if(p->B > 255)p->B = 255;
			
			fwrite(&p->B , sizeof(char) , 1 , f);
			fwrite(&p->G , sizeof(char) , 1 , f);
			fwrite(&p->R , sizeof(char) , 1 , f);		
	

			p++;

		}//End of for
		
		//padding
		fwrite(&padding_b , sizeof(char) , _p , f); 



	}//End of for


return 0;

}//End of writeBMP


