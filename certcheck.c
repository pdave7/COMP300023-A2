/**
/*
Name : Parnak.Niranjan.Dave
Login ID: pdave

Simple C file that does TLS Certificate checking manually using appropriate functions and importing libraries 
from openssl to authenticate and validates TLS certificate files.

    The structure of starting the server has been borrowed from the server.c provided in labs.  
    The structure of starting out the TLS checking has been borrowed from the certexample.c file provided on gitlab by
    Chris Culnane.

    THINGS LEFT 
    * Magic numbers
    * Commenting and appropriate documentation 
    * clean up
    * makefile 
    * clean and flush all data
*/
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>


#define max_args 2

const char* getfield(char* line, int num);
const ASN1_TIME *X509_get0_notBefore(const X509 *x);
const ASN1_TIME *X509_get0_notAfter(const X509 *x);

//int ASN1_TIME_check(const ASN1_TIME *t);



int main(int argc, char *argv[])
{

    //const char test_cert_example[] = "./testthree.crt";
    BIO *certificate_bio;
    char *subj;
    char*substring; 
    char*input_substring;
    const char ch = '.';
    const char string2find = ".";
    const char CAcheck[] = "CA:TRUE";
    const char TLS[] = "TLS Web Server Authentication";

    //char *where;


    int count = 0;
    int count_1 = 0;
    char *tmp;
    char file_print_out[20];

    const int extension_check = 00;
    const int extension_check_2 = 04;



    BIO *b;
    b = BIO_new_fp(stdout, BIO_NOCLOSE); 
    int day, sec;

    BIO *STDout = NULL;
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);


    char printbio[256];
    char *p;
    

    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    const ASN1_TIME* notBefore = NULL;
    const ASN1_TIME* notAfter = NULL;

    X509_NAME *subjectName;
    char  subjectCn[256];
    char SAN[256];
    int k;

    


    STACK_OF(X509_EXTENSION) * ext_list;
    

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    FILE* stream = NULL;
    char file_name[12] = "fileout.csv";
    FILE *f = fopen(file_name, "w"); 
    char *fileptr;
    char read_file_location[40];
    char first_input[1024]; 

    if(argc != max_args){
        //printf("\nNot enough arguments passed to test the script\n");
    }
    else {
        strcpy(read_file_location,argv[1]);
        
        //printf("%s\n",fileptr);
        //stream = read_file;
        //printf("%s\n", stream);
        stream = fopen(read_file_location, "r+");
        while(fgets (first_input , 1024 , stream)){

            int valid = 1;

            char* temp = strdup(first_input);
            char* temp_1 = strdup(first_input);

            char* input_1 = getfield(temp,1);
            char* input_2 = getfield(temp_1,2);
            char* DN = strdup(first_input);


            /*getfield(temp,1);
            printf("temp: %s\n", temp); */

            if (!(BIO_read_filename(certificate_bio, input_1)))

            {

                fprintf(stderr, "Error in reading cert BIO filename");
                exit(EXIT_FAILURE);
            }
            if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
            {
                fprintf(stderr, "Error in loading certificate");
                exit(EXIT_FAILURE);
            }



            //file_print_out = (char *) malloc(sizeof(char) * strlen(input_2));
            strcpy(file_print_out, input_2);
            printf("%s\n", file_print_out);
            notBefore = X509_get0_notBefore(cert);
            notAfter = X509_get0_notAfter(cert);
            subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            EVP_PKEY * public_key = X509_get_pubkey(cert);
            RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
            int key_length = RSA_size(rsa_key)*8;

            if(key_length >= 2048){
                //printf("%d\n",key_length);
            }
            else{
                valid = 0;
            }

            subjectName = X509_get_subject_name(cert);
            X509_NAME_get_text_by_NID(subjectName, NID_commonName, subjectCn, sizeof(subjectCn));

    //X509_NAME_get_text_by_NID(subjectName, NID_subject_alt_name, SAN, sizeof(SAN));


            tmp = (char *) malloc(sizeof(char) * strlen(input_2 + 1));
            strcpy(tmp, input_2);

            //temp_1 = (char *) malloc(sizeof(char) * strlen(input_2 + 1));
   // printf("tmp : %s\n",tmp);
    //printf("CN: %s\n", subjectCn);

            for(count=0; tmp[count]; tmp[count]=='.' ? count++ : *tmp++);




            substring = strchr(subjectCn,ch);
            input_substring = strchr(input_2, ch);

            if(input_substring != NULL)
            {
                *input_substring = '\0'; /* overwrite first separator, creating two strings. */
        //printf("first part: '%s'\nsecond part: '%s'\n", a, sep_at + 1);
        //printf("input substring: %s\n",input_substring+1);   
            }

            if(count > 1){
                if(substring != NULL)
                {
                    *substring = '\0'; /* overwrite first separator, creating two strings. */
        //printf("first part: '%s'\nsecond part: '%s'\n", a, sep_at + 1);
            //printf("substring: %s\n",substring+1);   
                }
            }    


 


            if((strcmp(input_substring+1, substring+1) == 0)){
                //printf("equal wildcard\n");
            }
            else{
                valid = 0;
            }


    //printf("CN: %s\n", subjectCn);
    //printf("Seperated: %s\n", substring );
    //printf("DN: %s\n", getfield(DN,2));
    //k = strcmp(subjectCn,getfield(temp,2));

            ASN1_TIME_diff(&day, &sec, NULL, notBefore);

            if (day > 0 || sec > 0){
                valid = 0;
                //printf("Later\n");
            }
            else if (day < 0 || sec < 0){
                //printf("Sooner\n");
            }
            else{
                //printf("Same\n");
            }

            ASN1_TIME_diff(&day, &sec, NULL, notAfter);

            if (day > 0 || sec > 0){
                //printf("Later\n");
            }
            else if (day < 0 || sec < 0){
                valid = 0;
                //printf("Sooner\n");
            }
            else{
                //printf("Same\n");
            }


            cert_inf = cert->cert_info;
            ext_list = cert_inf->extensions;
            ASN1_OBJECT *obj;
            X509_EXTENSION *ext;
            X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));

            ext = sk_X509_EXTENSION_value(ext_list, extension_check);
    //obj = X509_EXTENSION_get_object(ext);
            BUF_MEM *bptr = NULL;
            char *buf = NULL;

            BIO *bio = BIO_new(BIO_s_mem());
            if (!X509V3_EXT_print(bio, ext, 0, 0))
            {
                fprintf(stderr, "Error in reading extensions");
            }
            BIO_flush(bio);
            BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
            buf = (char *)malloc((bptr->length + 1) * sizeof(char));
            memcpy(buf, bptr->data, bptr->length);
            buf[bptr->length] = '\0';

            if((strcmp(buf,CAcheck))==0){
                valid = 0;
                //printf("CA is true\n");
            }

    //Can print or parse value
            //printf("buf: %s\n", buf);
    //printf("CA: %s\n", CAcheck);
            ext = sk_X509_EXTENSION_value(ext_list, extension_check_2);
            char *TLS_buf = NULL;
            BIO *bio_1 = BIO_new(BIO_s_mem());
            if (!X509V3_EXT_print(bio_1, ext, 0, 0))
            {
                fprintf(stderr, "Error in reading extensions");
            }
            BIO_flush(bio_1);
            BIO_get_mem_ptr(bio_1, &bptr);

    //bptr->data is not NULL terminated - add null character
            TLS_buf = (char *)malloc((bptr->length + 1) * sizeof(char));
            memcpy(TLS_buf, bptr->data, bptr->length);
            TLS_buf[bptr->length] = '\0';

            //printf("tls BUF :%s\n", TLS_buf);
            //printf("tls check: %s\n",TLS );
            p = strstr (TLS_buf,TLS);

            if(p){
                //printf("Authenticated\n");
            }
            else{
                valid = 0;
            }

    /*if((strcmp(TLS_buf, TLS)) == 0){
        printf("TLS web authenticated\n\n\n\n");
    }*/
            GENERAL_NAMES *sANs;

            if( !( sANs = X509_get_ext_d2i( cert, NID_subject_alt_name, 0, 0 ))) {
                //printf( "No subjectAltName extension\n" );
            }

            char* SAN_substring;
            int i, numAN = sk_GENERAL_NAME_num( sANs );
            //printf( "subjectAltName entries: %d\n", numAN );
            for( i = 0; i < numAN; ++i ) {
                GENERAL_NAME *sAN = sk_GENERAL_NAME_value( sANs, i );
        // we only care about DNS entries
                if( GEN_DNS == sAN->type ) {
                    unsigned char *dns;
                    ASN1_STRING_to_UTF8( &dns, sAN->d.dNSName );
                    SAN_substring = strchr(dns,ch);
            //printf("SANSUB: %s\n", SAN_substring+1);
            //printf("input_substring: %s\n", input_substring + 1);
                    if(strcmp(SAN_substring+1,input_substring+1) == 0){
                        valid = 1;
                        //printf("SAN MATCHED\n");
                    }
            //printf( "subjectAltName DNS: %s\n", dns );
                    OPENSSL_free( dns );
                }
            }
            //printf("input2 :%s\n", file_print_out);

        fprintf(f, "%s,%s,%d\n",input_1,file_print_out,valid);
        BIO_free_all(bio);
    //free(buf);
        BIO_flush(bio);
        }
        //BIO_flush(bio);
        X509_free(cert);
        BIO_free_all(certificate_bio);
            //printf("Field 1 is %s\n", getfield(temp,2));
    }

    exit(0);

    //Read certificate into BIO
    
}



const ASN1_TIME *X509_get0_notBefore(const X509 *x)
{
    return x->cert_info->validity->notBefore;
}

const ASN1_TIME *X509_get0_notAfter(const X509 *x)
{
    return x->cert_info->validity->notAfter;
}

const char* getfield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ",");
        tok && *tok;
        tok = strtok(NULL, ";\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}