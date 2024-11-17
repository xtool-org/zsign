#include <signer.h>

int zsign_sign(const char *app_directory,
               const void *cert_data,
               size_t cert_len,
               const void *private_key_data,
               size_t private_key_len,
               const entitlements_data_t *entitlements,
               size_t num_entitlements,
               void (*progress)(const void *, double),
               const void *progressContext,
               char **exception);

void *zsign_analyze(const char *path,
                    size_t *out_len,
                    char **exception);
