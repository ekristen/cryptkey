// This file calls fido_init(FIDO_DISABLE_U2F_FALLBACK) via a GCC
// constructor before go-libfido2's init() runs fido_init(0). The U2F
// fallback path probes PC/SC readers, which grabs an exclusive handle
// and prevents go-piv from establishing its own PC/SC context for PIV
// operations. Disabling the fallback lets both providers coexist.
//
// fido_init ignores subsequent calls (libfido2 >= 1.5), so the
// upstream init() becomes a no-op.
package fido2

/*
#include <fido.h>

// GCC constructor with priority 101 runs before the default-priority
// constructors that CGO generates for Go init() functions.
static void __attribute__((constructor(101))) cryptkey_fido_preinit(void) {
	fido_init(FIDO_DISABLE_U2F_FALLBACK);
}
*/
import "C"
