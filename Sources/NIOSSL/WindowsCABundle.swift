//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(Windows)
@_implementationOnly import CNIOBoringSSL
import WinSDK

/// Load the certificates in the Windows "ROOT" system store into the context's
/// trust store: the platform default trust on Windows.
///
/// Without this, `.default` trust roots on Windows were an empty store, so a
/// client verifying a server certificate rejected every certificate, including
/// ones the operating system trusts.
///
/// The store is read once per context, which is what the Linux path does with
/// its bundle file. Certificates BoringSSL cannot parse are skipped, as are
/// duplicates (`X509_STORE_add_cert` reports those as an error, which is
/// cleared).
internal func loadWindowsSystemRoots(into context: OpaquePointer) throws {
    guard let trustStore = SSL_CTX_get_cert_store(context) else {
        throw NIOSSLError.failedToLoadCertificate
    }
    let systemStore = "ROOT".withCString(encodedAs: UTF16.self) { name in
        CertOpenSystemStoreW(0, name)
    }
    guard let systemStore else {
        throw NIOSSLError.failedToLoadCertificate
    }
    defer { CertCloseStore(systemStore, 0) }

    var added = 0
    var certificate: PCCERT_CONTEXT? = nil
    while let next = CertEnumCertificatesInStore(systemStore, certificate) {
        certificate = next
        // X509_ASN_ENCODING; spelled out because wincrypt's name for it is
        // shadowed by BoringSSL's X509 declarations.
        guard next.pointee.dwCertEncodingType & 0x1 != 0,
            let encoded = next.pointee.pbCertEncoded
        else { continue }
        var cursor: UnsafePointer<UInt8>? = UnsafePointer(encoded)
        // `long` is 32 bits on Windows.
        guard let x509 = d2i_X509(nil, &cursor, numericCast(next.pointee.cbCertEncoded)) else { continue }
        if X509_STORE_add_cert(trustStore, x509) == 1 { added += 1 }
        X509_free(x509)
    }
    // Duplicates and unparseable entries leave errors on the queue that would
    // otherwise surface in an unrelated later operation.
    ERR_clear_error()
    if added == 0 {
        throw NIOSSLError.failedToLoadCertificate
    }
}
#endif
