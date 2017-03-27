// Package crypto wraps many of the standard Go crypto tools. The most significant
// feature is providing types that distinguish XchgPublic and XchgPrivate keys, rather
// than using slices or arrays of bytes directly.
//
// Crypto also provides an Un-MAC'd variant of the tools from
// golang.org/x/crypto/nacl/secretbox. Trusting un-MAC'd data is never a good
// idea, but in the Leap Frog onion routing protocol, layers of encryption are
// added on to MAC'd data, providing the necesary safety.
//
// There are a number of rare and unlikely errors that all stem from not being
// able to generate random cryptographic data. In this case (and only this case)
// we do not use the idiomatic Go technique of bubbling the error up. Generally,
// nothing can be done, so we panic. If you don't want to panic, the error is
// placed on ErrChan, along with ErrConfirm. This lets the error handler read
// the error but keeps blocking the crypto function until it's addressed. Only
// when ErrConfirm is pulled can the function return. All functions that use
// this feature are used to generate crypto objects (keys and nonces). They will
// return nil if there is an error.
//
// tl;dr: don't use unmac'd ciphers alone, only use them on top of MAC'd data.
// If you don't want to worry about ErrChan, just set PanicOnError to true.
package crypto
