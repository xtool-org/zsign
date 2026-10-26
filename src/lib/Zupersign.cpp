#include <Zupersign.h>
#include <openssl/err.h>
#include "openssl.h"
#include "macho.h"
#include "bundle.h"
#include "signing.h"
#include <list>

static void print_ssl_err(char **exception, const char *reason) {
    unsigned long last_error = ERR_peek_last_error();
    if (!last_error) {
        *exception = strdup(reason);
        return;
    }
    asprintf(exception,
             "%s (error:%lx:%s:%s)",
             reason,
             last_error,
             ERR_lib_error_string(last_error),
             ERR_reason_error_string(last_error));
}

int zsign_sign(
    const char *app_directory,
    const void *cert_data,
    size_t cert_len,
    const void *private_key_data,
    size_t private_key_len,
    const entitlements_data_t *entitlements,
    size_t num_entitlements,
    void (*progress)(const void *, double),
    const void *progressContext,
    char **exception
) {
    bool success;

    if (num_entitlements == 0) {
        *exception = strdup("No entitlements provided");
        return -1;
    }

    progress(progressContext, -1);

    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;

    bool is_adhoc = private_key_len == 0 || cert_len == 0;

    if (!is_adhoc) {
        ERR_clear_error();
        BIO *private_key_bio = BIO_new_mem_buf(private_key_data, (int)private_key_len);
        if (!private_key_bio) {
            print_ssl_err(exception, "Missing private key");
            return -1;
        }
        pkey = PEM_read_bio_PrivateKey(private_key_bio, NULL, NULL, NULL);
        BIO_free(private_key_bio);
        if (!pkey) {
            print_ssl_err(exception, "Invalid private key");
            return -1;
        }

        cert = d2i_X509(NULL, (const unsigned char **)&cert_data, cert_len);
        if (!cert) {
            print_ssl_err(exception, "Invalid developer certificate");
            EVP_PKEY_free(pkey);
            return -1;
        }
    }

    // One asset per entitlements set. The one for the app itself (or the first one if none
    // is bound to the app) is the default; the others apply to the nested bundle at their path.
    string appRoot(app_directory);
    while (appRoot.size() > 1 && appRoot.back() == '/') {
        appRoot.pop_back();
    }
    std::list<ZSignAsset> assets;
    size_t defaultIndex = 0;
    for (size_t i = 0; i < num_entitlements; i++) {
        assets.emplace_back();
        ZSignAsset &asset = assets.back();
        success = asset.Init(
            cert, pkey, "",
            string(static_cast<const char *>(entitlements[i].data), entitlements[i].len),
            is_adhoc, false, false
        );
        if (!success) {
            *exception = strdup("Invalid developer certificate/private key");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            return -1;
        }

        string path(entitlements[i].bundle_path ? entitlements[i].bundle_path : "");
        while (path.size() > 1 && path.back() == '/') {
            path.pop_back();
        }
        if (path == appRoot) {
            asset.m_strBundlePath = "/";
            defaultIndex = i;
        } else if (path.size() > appRoot.size() + 1 && path.compare(0, appRoot.size() + 1, appRoot + "/") == 0) {
            asset.m_strBundlePath = path.substr(appRoot.size() + 1);
        }
    }
    // the default asset must come first: SignFolder uses the front of the list
    if (defaultIndex != 0) {
        auto it = assets.begin();
        std::advance(it, defaultIndex);
        assets.splice(assets.begin(), assets, it);
    }

    ZBundle bundle;
    success = bundle.SignFolder(
        &assets,
        app_directory,
        "",
        "",
        "",
        std::vector<string>(),
        std::vector<string>(),
        true,
        false,
        false
    );

    EVP_PKEY_free(pkey);
    X509_free(cert);

    if (!success) {
        *exception = strdup("Signing failed");
        return -1;
    }

    return 0;
}

void *zsign_analyze(const char *path, size_t *out_len, char **exception) {
    ZMachO macho;
    if (!macho.Init(path)) {
        *exception = strdup("ZMachO::Init failed");
        return NULL;
    }

    auto &archs = macho.m_arrArchOes;
    if (archs.empty()) {
        *exception = strdup("ZMachO::m_arrArchOes is empty");
        return NULL;
    }

    auto &arch = *archs.front();
    string entitlements;
    if (!ZSign::ParseCodeSignatureEntitlements(arch.m_pSignBase, entitlements)) {
        *exception = strdup("ParseCodeSignatureEntitlements failed");
        return NULL;
    }

    size_t ents_size = entitlements.size();
    *out_len = ents_size;
    void *out = malloc(ents_size);
    memcpy(out, entitlements.data(), ents_size);
    return out;
}

__attribute__((constructor)) static void ctor() {
    ZLog::SetLogLever(ZLog::eLogType::E_ERROR);
    add_signer("zsign", zsign_sign, zsign_analyze);
}
