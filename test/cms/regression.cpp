#include "common.h"
#include <fstream>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#define private public
#include "openssl.h"
#undef private

static void require(bool result, const char* what) {
    if (!result) { fprintf(stderr, "FAIL: %s\n", what); ERR_print_errors_fp(stderr); exit(3); }
}
static string digest(const string& input, const EVP_MD* algorithm) {
    unsigned char value[EVP_MAX_MD_SIZE]; unsigned int count=0;
    require(EVP_Digest(input.data(), input.size(), value, &count, algorithm, nullptr)==1, "digest");
    return string(reinterpret_cast<char*>(value), count);
}
static string read(const char* path) {
    std::ifstream file(path, std::ios::binary);
    require(file.good(), "read code directory");
    return string(std::istreambuf_iterator<char>(file), {});
}
static void write(const char* path, const string& data) {
    std::ofstream file(path, std::ios::binary); file.write(data.data(),data.size());
    require(file.good(), "write synthetic CMS");
}
int main(int argc, char**argv) {
#ifndef BASELINE
    if (argc==2 && string(argv[1])=="helper") {
        for(int i=0;i<1000;i++) {
            for(const char* alg : {"sha1","sha256"}) {
                auto *v=(ASN1_TYPE*)ZSignAsset::GenerateASN1Type("0080FF",alg);
                require(v && v->type==V_ASN1_SEQUENCE,"helper valid"); ASN1_TYPE_free(v);
            }
            require(!ZSignAsset::GenerateASN1Type("GG","sha256"),"helper rejects invalid hex"); ERR_clear_error();
            require(!ZSignAsset::GenerateASN1Type("00","sha512"),"helper rejects algorithm");
            require(!ZSignAsset::GenerateASN1Type("00","sha256\nmalicious=value"),"helper rejects injected algorithm");
        }
        puts("PASS helper: 2,000 valid allocations freed; malformed hex and unsupported/injected algorithms rejected");
        return 0;
    }
#endif
    require(argc==5,"usage: primary alternate output expected-count");
    string primary=read(argv[1]), alternate=read(argv[2]);
    string one=digest(primary,EVP_sha1()),two=digest(alternate,EVP_sha256());
    EVP_PKEY_CTX* keyctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);
    require(keyctx && EVP_PKEY_keygen_init(keyctx)>0 && EVP_PKEY_CTX_set_rsa_keygen_bits(keyctx,2048)>0,"key init");
    EVP_PKEY* key=nullptr; require(EVP_PKEY_keygen(keyctx,&key)>0,"keygen"); EVP_PKEY_CTX_free(keyctx);
    BIO* caBIO=BIO_new_mem_buf(ZSignAsset::s_szAppleDevCACertG3,-1);
    X509* ca=PEM_read_bio_X509(caBIO,nullptr,nullptr,nullptr); BIO_free(caBIO); require(ca,"public CA parse");
    X509* cert=X509_new(); require(cert,"cert allocation");
    X509_set_version(cert,2); ASN1_INTEGER_set(X509_get_serialNumber(cert),1);
    X509_gmtime_adj(X509_getm_notBefore(cert),-60); X509_gmtime_adj(X509_getm_notAfter(cert),3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert),"CN",MBSTRING_ASC,(const unsigned char*)"Synthetic signer verification",-1,-1,0);
    require(X509_set_issuer_name(cert,X509_get_subject_name(ca))==1 && X509_set_pubkey(cert,key)==1 && X509_sign(cert,key,EVP_sha256())>0,"synthetic cert");
    ZSignAsset signer;
    string output;
    require(signer.GenerateCMS(cert,key,primary,"<plist><dict/></plist>",one,two,output),"GenerateCMS success");
    write(argv[3],output);
    const unsigned char* pointer=(const unsigned char*)output.data();
    CMS_ContentInfo* cms=d2i_CMS_ContentInfo(nullptr,&pointer,output.size()); require(cms,"decode CMS");
    STACK_OF(CMS_SignerInfo)* signers=CMS_get0_SignerInfos(cms); require(sk_CMS_SignerInfo_num(signers)==1,"one signer");
    CMS_SignerInfo* si=sk_CMS_SignerInfo_value(signers,0);
    ASN1_OBJECT* oid=OBJ_txt2obj("1.2.840.113635.100.9.2",1);
    int loc=CMS_signed_get_attr_by_OBJ(si,oid,-1); require(loc>=0,"v2 attribute present");
    require(CMS_signed_get_attr_by_OBJ(si,oid,loc)==-1,"one v2 attribute"); ASN1_OBJECT_free(oid);
    X509_ATTRIBUTE* attr=CMS_signed_get_attr(si,loc);
    int count=X509_ATTRIBUTE_count(attr); printf("v2 entries=%d\n",count);
    require(count==atoi(argv[4]),"expected directory count");
    std::map<int,string> actual;
    for(int i=0;i<count;i++) {
        ASN1_TYPE* value=X509_ATTRIBUTE_get0_type(attr,i); require(value && value->type==V_ASN1_SEQUENCE,"sequence value");
        const unsigned char* p=ASN1_STRING_get0_data(value->value.sequence);
        long size=ASN1_STRING_length(value->value.sequence);
        STACK_OF(ASN1_TYPE)* seq=d2i_ASN1_SEQUENCE_ANY(nullptr,&p,size);
        require(seq && sk_ASN1_TYPE_num(seq)==2,"algorithm digest pair");
        ASN1_TYPE* a=sk_ASN1_TYPE_value(seq,0),*d=sk_ASN1_TYPE_value(seq,1);
        require(a->type==V_ASN1_OBJECT && d->type==V_ASN1_OCTET_STRING,"OID and octets");
        int nid=OBJ_obj2nid(a->value.object);
        require(!actual.count(nid),"distinct digest algorithms");
        actual[nid]=string((const char*)ASN1_STRING_get0_data(d->value.octet_string),ASN1_STRING_length(d->value.octet_string));
        sk_ASN1_TYPE_pop_free(seq,ASN1_TYPE_free);
    }
    if (count==2) require(actual[NID_sha1]==one && actual[NID_sha256]==two,"full exact code-directory digests");
    else require(actual[NID_sha256]==two,"baseline SHA256 digest");
    BIO* data=BIO_new_mem_buf(primary.data(),primary.size()); BIO* sink=BIO_new(BIO_s_null());
    require(CMS_verify(cms,nullptr,nullptr,data,sink,CMS_NO_SIGNER_CERT_VERIFY|CMS_BINARY)==1,"CMS signature verifies"); BIO_free(data); BIO_free(sink);
    ASN1_TYPE* first=X509_ATTRIBUTE_get0_type(attr,0);
    first->value.sequence->data[first->value.sequence->length-1]^=1;
    data=BIO_new_mem_buf(primary.data(),primary.size()); sink=BIO_new(BIO_s_null());
    require(CMS_verify(cms,nullptr,nullptr,data,sink,CMS_NO_SIGNER_CERT_VERIFY|CMS_BINARY)==0,"tampered signed digest rejected"); BIO_free(data); BIO_free(sink); ERR_clear_error();
    CMS_ContentInfo_free(cms);
#ifndef BASELINE
    for(size_t size : {0,1,19,21,31,33}) {
        string result="sentinel";
        require(!signer.GenerateCMS(cert,key,primary,"<plist/>",string(size,'a'),two,result),"wrong SHA1 length rejects");
        require(result=="sentinel","invalid SHA1 produces no CMS");
        require(!signer.GenerateCMS(cert,key,primary,"<plist/>",one,string(size,'a'),result),"wrong SHA256 length rejects");
        require(result=="sentinel","invalid SHA256 produces no CMS");
    }
    puts("PASS 12 invalid digest length cases produce no output CMS");
#endif
    X509_free(cert);X509_free(ca);EVP_PKEY_free(key);
    puts("PASS full digests, distinct algorithms, signed attribute tamper rejection");
}
