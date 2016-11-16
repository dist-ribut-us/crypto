// Package crypto wraps many of the standard Go crypto tools. The most significant
// feature is providing types that distinguish Public and Private keys, rather
// than using slices or arrays of bytes directly.
//
// Crypto also provides an Un-MAC'd variant of the tools from
// golang.org/x/crypto/nacl/secretbox. Trusting un-MAC'd data is never a good
// idea, but in the Leap Frog onion routing protocol, layers of encryption are
// added on to MAC'd data, providing the necesary safety.
//
// tl;dr: don't use unmac'd ciphers alone, only use them on top of MAC'd data.
package crypto
