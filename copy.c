/**
    Example certifcate code
    gcc -o certexample certexample.c -lssl -lcrypto
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
    BIO *certificate_bio = NULL;
    char *subj;

    BIO *b;
    b = BIO_new_fp(stdout, BIO_NOCLOSE); 
    int day, sec;

    BIO *STDout = NULL;
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);


    char printbio[256];

    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    const ASN1_TIME* notBefore = NULL;
    const ASN1_TIME* notAfter = NULL;

    X509_NAME *subjectName;
    char  subjectCn[256];
    int k;

  

    STACK_OF(X509_EXTENSION) * ext_list;
    

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    FILE* stream = NULL;
    char *fileptr;
    char read_file_location[40];
    char first_input[1024]; 
    if(argc != max_args){
        printf("\nNot enough arguments passed to test the script\n");
    }
    else {
        strcpy(read_file_location,argv[1]);
        
        //printf("%s\n",fileptr);
        //stream = read_file;
        //printf("%s\n", stream);
        stream = fopen(read_file_location, "r+");
        while(fgets (first_input , 1024 , stream)){

            char* temp = strdup(first_input);
            char* DN = strdup(first_input);

            /*getfield(temp,1);
            printf("temp: %s\n", temp); */

            if (!(BIO_read_filename(certificate_bio, getfield(temp,1))))

    {

        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }
                    printf("here\n");


    //printf("DN: %s\n", getfield(DN,2));

    notBefore = X509_get0_notBefore(cert);
    notAfter = X509_get0_notAfter(cert);
    subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);


   
    subjectName = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(subjectName, NID_commonName, subjectCn, sizeof(subjectCn));
    //BIO_puts(STDout, "notBefore=");
    //ASN1_TIME_print(STDout, X509_getm_notBefore(cert));
    //BIO_puts(STDout, "\n");
    //printf("not before \n");
    //ASN1_TIME_print(b,notBefore);
    //if(ASN1_TIME_check(notBefore)){
    //    printf("after\n");
    //}
    //else{
    //   printf("before\n");
    //}

    /*ASN1_TIME_diff(&day, &sec, NULL, notBefore);
     /* Invalid time format 

    if (day > 0 || sec > 0){
        printf("Later\n");
    }
    else if (day < 0 || sec < 0){
        printf("Sooner\n");
    }
    else{
        printf("Same\n");
    }*/
    printf("CN: %s\n", subjectCn);
    //k = strcmp(subjectCn,getfield(temp,2));
   
    ASN1_TIME_diff(&day, &sec, notAfter, NULL);

     if (day > 0 || sec > 0){
        printf("Later\n");
    }
    else if (day < 0 || sec < 0){
        printf("Sooner\n");
    }
    else{
        printf("Same\n");
    }

    k = strcmp(getfield(DN,2),subjectCn);
        printf("%d\n",k);
    

    //ASN1_TIME_set_string(notBefore, printbio);
    //BIO_printf(certificate_bio,"here\n");
   // printf("%s\n",printbio);

    //cert contains the x509 certificate and can be used to analyse the certificate
    
    //*********************
    // Example code of accessing certificate values
    //*********************

    cert_issuer = X509_get_issuer_name(cert);
    char issuer_cn[256] = "Issuer CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
    printf("Issuer CommonName:%s\n", issuer_cn);

    //List of extensions available at https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_get0_extensions.html
    //Need to check extension exists and is not null
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    printf("Extension:%s\n", buff);

    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    //Can print or parse value
    printf("%s\n", buf);

    //*********************
    // End of Example code
    //*********************

    BIO_free_all(bio);
    //free(buf);
    X509_free(cert);
    BIO_free_all(certificate_bio);

            }

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