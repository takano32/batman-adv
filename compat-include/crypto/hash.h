#ifndef _NET_BATMAN_ADV_COMPAT_CRYPTO_HASH_H_
#define _NET_BATMAN_ADV_COMPAT_CRYPTO_HASH_H_

#include <linux/version.h>
#include_next <crypto/hash.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)

#define SHASH_DESC_ON_STACK(shash, ctx)				  \
	char __##shash##_desc[sizeof(struct shash_desc) +	  \
		crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc

#endif /* < KERNEL_VERSION(3, 18, 0) */

#endif	/* _NET_BATMAN_ADV_COMPAT_CRYPTO_HASH_H_ */
