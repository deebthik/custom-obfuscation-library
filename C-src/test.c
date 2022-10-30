
#include <string.h>
#include <stdio.h>

int main(){


/*char z[100];
strcpy(z,"000000efhelfwefwefEFG00EFWEFhb");
int n;
if( ( n = strspn(z, "0" ) ) != 0 && z[n] != '\0' ) {
  sprintf(z, "%s", &z[n]);
printf(" Trimmed string is %s \n", z);
}*/

char bla[32];
strcpy(bla, "2134567");
int len = strlen(bla);


if (len < 8 && len >5){
char bla_temp[8];
	if (len == 7){
	strcpy(bla_temp, "0");
}
else if (len == 6){
strcpy(bla_temp, "00");
}
	strcat(bla_temp, bla);
	sprintf(bla, "%s", bla_temp);
}
	printf("final padded str %s\n", bla);




}
