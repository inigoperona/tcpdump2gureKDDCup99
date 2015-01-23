#include <stdio.h>
#include <string.h>

#define MaxCon 800000
#define MaxLine 800
#define MaxToken 20

char inigo[MaxCon][MaxLine];
int inigoKop;

int main(int argc, char **argv)
{
	FILE *finigo, *ftrafAld;
	int i,j;
	char galdera[MaxLine];
	int noraino;
	int nondik2, nondik100;
	char line[MaxLine];	
	
	//Uneko konexioaren datuak
	char line1[MaxLine];
	int konZenb1;
	char hasUnea1s[MaxToken];
	int hasUnea1, hasUnea12;
	int orig_p1,resp_p1;
	char orig_h1[MaxToken], resp_h1[MaxToken];
	char duration1[MaxToken], protokoloa1[MaxToken], service1[MaxToken], flag1[MaxToken];
	
	//Aurreko konexioen datuentzat
	char line2[MaxLine];
	int konZenb2;
	char hasUnea2s[MaxToken];
	int hasUnea2, hasUnea22;
	int orig_p2,resp_p2;
	char orig_h2[MaxToken], resp_h2[MaxToken];
	char duration2[MaxToken], protokoloa2[MaxToken], service2[MaxToken], flag2[MaxToken];
	int sartuDa2;
	
	//trafiko aldagaientzat
	int count,srv_count,serror,rerror,same_srv,diff_srv,srv_serror,srv_error,srv_diff_host;
	int same_src_port;
	float serror_rate,srv_serror_rate,rerror_rate,srv_error_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate;
	float srv_rerror_rate,same_src_port_rate;

	if (argc != 2){
	  printf("Deia: %s inigo.list\n", argv[0]);
		return(1);
	}

  //inigo.list irakurri eta gorde
  sprintf(galdera, "%s", argv[1]);
  finigo = fopen(galdera, "r");
  inigoKop = 0;
  while(!feof(finigo)){
  	fgets(line2, MaxLine, finigo);
   	line2[strlen(line2)-1] = '\0';
    strcpy(inigo[inigoKop],line2);
    inigoKop = inigoKop + 1;
  }
  fclose(finigo);
  inigoKop = inigoKop - 1; //feof-z lerro bat gehiago irakurtzen baita

	//trafiko aldagaiak kalkulatu
	nondik2=0;
	for(noraino=0; noraino<inigoKop; noraino++){
		strcpy(line1, inigo[noraino]);
		sscanf(line1, "%d %s %d %d %s %s %s %s %s %s %s",
                   &konZenb1,&hasUnea1s,&orig_p1,&resp_p1,&orig_h1,&resp_h1,
                   &duration1,&protokoloa1,&service1,&flag1);
		sscanf(hasUnea1s, "%d.%d", &hasUnea1, &hasUnea12);
		orig_h1[strlen(orig_h1)] = '\0';
		resp_h1[strlen(resp_h1)] = '\0';
		service1[strlen(service1)] = '\0';
		flag1[strlen(flag1)] = '\0';
		
		//azken 2 segunduetako konexioak
		sartuDa2=0;
		count=0;
		serror=0;
		rerror=0;
		same_srv=0;
		diff_srv=0;
		srv_count=0;
		srv_serror=0;
		srv_error=0;
		srv_diff_host=0;
		for(j=nondik2; j<noraino; j++){
			strcpy(line2, inigo[j]);
			sscanf(line2, "%d %s %d %d %s %s %s %s %s %s %s",
			      		&konZenb2,&hasUnea2s,&orig_p2,&resp_p2,&orig_h2,&resp_h2,
					&duration2,&protokoloa2,&service2,&flag2);
			sscanf(hasUnea2s, "%d.%d", &hasUnea2, &hasUnea22);
			orig_h2[strlen(orig_h2)] = '\0';
			resp_h2[strlen(resp_h2)] = '\0';
			service2[strlen(service2)] = '\0';
			flag2[strlen(flag2)] = '\0';
			if((hasUnea1-2)<=hasUnea2 && hasUnea2<=hasUnea1){
				if(sartuDa2==0){ 
					nondik2=j;
					sartuDa2=1;
				}
				if (strcmp(resp_h1,resp_h2)==0){
					count= count + 1;
					if (strcmp(flag2,"S0")==0 || strcmp(flag2,"S1")==0 || strcmp(flag2,"S2")==0 || strcmp(flag2,"S3")==0){
						serror= serror + 1;
					}
					if (strcmp(flag2,"REJ")==0){
						rerror= rerror + 1;
					}
					if (strcmp(service2,"other")!=0 && strcmp(service1,service2)==0){
						same_srv= same_srv + 1;
					}
					if (strcmp(service1,service2)!=0){
						diff_srv= diff_srv + 1;
					}	
				}
				if (resp_p1==resp_p2){
					srv_count= srv_count + 1;
					if (strcmp(flag2,"S0")==0 || strcmp(flag2,"S1")==0 || strcmp(flag2,"S2")==0 || strcmp(flag2,"S3")==0){
						srv_serror= srv_serror + 1;
					}
					if (strcmp(flag2,"REJ")==0){
						srv_error= srv_error + 1;
					}
					if (strcmp(resp_h1,resp_h2)!=0){
						srv_diff_host= srv_diff_host + 1;
					}
				}				
			}
		}
		if (count!=0){
			serror_rate=(float)serror/(float)count;
			rerror_rate=(float)rerror/(float)count;
			same_srv_rate=(float)same_srv/(float)count;
			diff_srv_rate=(float)diff_srv/(float)count;
		}
		else{
			serror_rate= (float)0;
			rerror_rate= (float)0;
			same_srv_rate= (float)0;
			diff_srv_rate= (float)0;
		}
		if (srv_count!=0){
			srv_serror_rate=(float)srv_serror/(float)srv_count;
			srv_error_rate=(float)srv_error/(float)srv_count;
			srv_diff_host_rate=(float)srv_diff_host/(float)srv_count;
		}
		else{
			srv_serror_rate= (float)0;
			srv_error_rate= (float)0;
			srv_diff_host_rate= (float)0;
		}
		sprintf(line, "%s %d %d %f %f %f %f %f %f %f", 
							line1, 
							count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_error_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate);
		line[strlen(line)] = '\0';
		strcpy(inigo[noraino],line);

		//azken 100 konexioak
		if(noraino<=100){
			nondik100=0;
		}
		else{
			nondik100=noraino-100;
		}
		count=0;
		serror=0;
		rerror=0;
		same_srv=0;
		diff_srv=0;
		srv_count=0;
		srv_serror=0;
		srv_error=0;
		srv_diff_host=0;
		same_src_port=0;
		for(j=nondik100; j<noraino; j++){
			strcpy(line2, inigo[j]);
		  sscanf(line2, "%d %s %d %d %s %s %s %s %s %s %s",
		 		&konZenb2,&hasUnea2s,&orig_p2,&resp_p2,&orig_h2,&resp_h2,
		           	&duration2,&protokoloa2,&service2,&flag2);
		 	sscanf(hasUnea2s, "%d.%d", &hasUnea2, &hasUnea22);
		  orig_h2[strlen(orig_h2)] = '\0';
		  resp_h2[strlen(resp_h2)] = '\0';
		  service2[strlen(service2)] = '\0';
		  flag2[strlen(flag2)] = '\0';

			if (strcmp(resp_h1,resp_h2)==0){
      	count= count + 1;
        if (strcmp(flag2,"S0")==0 || strcmp(flag2,"S1")==0 || strcmp(flag2,"S2")==0 || strcmp(flag2,"S3")==0){
        	serror= serror + 1;
        }
      	if (strcmp(flag2,"REJ")==0){
      		rerror= rerror + 1;
      	}
        if (strcmp(service2,"other")!=0 && strcmp(service1,service2)==0){
         	same_srv= same_srv + 1;
       	}
        if (strcmp(service1,service2)!=0){
          diff_srv= diff_srv + 1;
        }
   		}
			if (resp_p1==resp_p2){
     		srv_count= srv_count + 1;
        if (strcmp(flag2,"S0")==0 || strcmp(flag2,"S1")==0 || strcmp(flag2,"S2")==0 || strcmp(flag2,"S3")==0){
        	srv_serror= srv_serror + 1;
       	}
        if (strcmp(flag2,"REJ")==0){
        	srv_error= srv_error + 1;
        }
        if (strcmp(resp_h1,resp_h2)!=0){
      		srv_diff_host= srv_diff_host + 1;
       	}
    	}
    	if (orig_p1==orig_p2){
    		same_src_port= same_src_port + 1;
    	}
		}
    if (count!=0){
      serror_rate=(float)serror/(float)count;
      rerror_rate=(float)rerror/(float)count;
      same_srv_rate=(float)same_srv/(float)count;
    	diff_srv_rate=(float)diff_srv/(float)count;
    }
    else{
    	serror_rate= (float)0;
      rerror_rate= (float)0;
      same_srv_rate= (float)0;
     	diff_srv_rate= (float)0;
   	}
		if (srv_count!=0){
			srv_serror_rate=(float)srv_serror/(float)srv_count;
		  srv_rerror_rate=(float)srv_error/(float)srv_count;
		  srv_diff_host_rate=(float)srv_diff_host/(float)srv_count;
		}
		else{
			srv_serror_rate= (float)0;
		  srv_rerror_rate= (float)0;
		  srv_diff_host_rate= (float)0;
		}
		if(noraino-nondik100!=0)
			same_src_port_rate=(float)same_src_port/(float)(noraino-nondik100);
		else
			same_src_port_rate=(float)0;

		strcpy(line1, inigo[noraino]);
    sprintf(line, "%s %d %d %f %f %f %f %f %f %f %f",
          		line1, 
    					count,srv_count,same_srv_rate,diff_srv_rate,same_src_port_rate,srv_diff_host_rate,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate);
  	line[strlen(line)] = '\0';
   	strcpy(inigo[noraino],line);
	}


	//idatzi trafAldagaiak
	sprintf(galdera, "trafAld.list");
	ftrafAld = fopen(galdera, "w");	
	for(i=0; i<inigoKop; i++){
		fprintf(ftrafAld, "%s\n", inigo[i]);
	}
	fclose(ftrafAld);	
}
