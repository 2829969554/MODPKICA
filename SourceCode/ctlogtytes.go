// CTExtensions is a representation of the raw bytes of any CtExtension
// structure (see section 3.2).
// nolint: revive
type CTExtensions []byte // tls:"minlen:0,maxlen:65535"`

// DigitallySigned is a local alias for tls.DigitallySigned so that we can
// attach a MarshalJSON method.
type DigitallySigned tls.DigitallySigned

// LogEntry represents the (parsed) contents of an entry in a CT log.  This is described
// in section 3.1, but note that this structure does *not* match the TLS structure
// defined there (the TLS structure is never used directly in RFC6962).
type LogEntry struct {
	Index int64
	Leaf  MerkleTreeLeaf
	// Exactly one of the following three fields should be non-empty.
	X509Cert *x509.Certificate // Parsed X.509 certificate
	Precert  *Precertificate   // Extracted precertificate
	JSONData []byte

	// Chain holds the issuing certificate chain, starting with the
	// issuer of the leaf certificate / pre-certificate.
	Chain []ASN1Cert
}
// ASN1Cert type for holding the raw DER bytes of an ASN.1 Certificate
// (section 3.1).
type ASN1Cert struct {
	Data []byte `tls:"minlen:1,maxlen:16777215"`
}
// PreCert represents a Precertificate (section 3.2).
type PreCert struct {
	IssuerKeyHash  [sha256.Size]byte
	TBSCertificate []byte `tls:"minlen:1,maxlen:16777215"` // DER-encoded TBSCertificate
}
// LogID holds the hash of the Log's public key (section 3.2).
// TODO(pphaneuf): Users should be migrated to the one in the logid package.
type LogID struct {
	KeyID [sha256.Size]byte
}

// PreCert represents a Precertificate (section 3.2).
type PreCert struct {
	IssuerKeyHash  [sha256.Size]byte
	TBSCertificate []byte `tls:"minlen:1,maxlen:16777215"` // DER-encoded TBSCertificate
}
// SignedCertificateTimestamp represents the structure returned by the
// add-chain and add-pre-chain methods after base64 decoding; see sections
// 3.2, 4.1 and 4.2.
type SignedCertificateTimestamp struct {
	SCTVersion Version `tls:"maxval:255"`
	LogID      LogID
	Timestamp  uint64
	Extensions CTExtensions    `tls:"minlen:0,maxlen:65535"`
	Signature  DigitallySigned // Signature over TLS-encoded CertificateTimestamp
}
// CertificateTimestamp is the collection of data that the signature in an
// SCT is over; see section 3.2.
type CertificateTimestamp struct {
	SCTVersion    Version       `tls:"maxval:255"`
	SignatureType SignatureType `tls:"maxval:255"`
	Timestamp     uint64
	EntryType     LogEntryType   `tls:"maxval:65535"`
	X509Entry     *ASN1Cert      `tls:"selector:EntryType,val:0"`
	PrecertEntry  *PreCert       `tls:"selector:EntryType,val:1"`
	JSONEntry     *JSONDataEntry `tls:"selector:EntryType,val:32768"`
	Extensions    CTExtensions   `tls:"minlen:0,maxlen:65535"`
}
// Version represents the Version enum from section 3.2:
//
//	enum { v1(0), (255) } Version;
type Version tls.Enum // tls:"maxval:255"
// CT Version constants from section 3.2.
const (
	V1 Version = 0
)
// JSONDataEntry holds arbitrary data.
type JSONDataEntry struct {
	Data []byte `tls:"minlen:0,maxlen:1677215"`
}

// SignatureType differentiates STH signatures from SCT signatures, see section 3.2.
//
//	enum { certificate_timestamp(0), tree_hash(1), (255) } SignatureType;
type SignatureType tls.Enum // tls:"maxval:255"
// SignatureType constants from section 3.2.
const (
	CertificateTimestampSignatureType SignatureType = 0
	TreeHashSignatureType             SignatureType = 1
)

// LogEntryType represents the LogEntryType enum from section 3.1:
//
//	enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
type LogEntryType tls.Enum // tls:"maxval:65535"
// LogEntryType constants from section 3.1.
const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType LogEntryType = 1
)

// SignatureAndHashAlgorithm gives information about the algorithms used for a
// signature.  Defined in RFC 5246 s7.4.1.4.1.
type SignatureAndHashAlgorithm struct {
	Hash      HashAlgorithm      `tls:"maxval:255"`
	Signature SignatureAlgorithm `tls:"maxval:255"`
}

// HashAlgorithm enum from RFC 5246 s7.4.1.4.1.
type HashAlgorithm Enum

// HashAlgorithm constants from RFC 5246 s7.4.1.4.1.
const (
	None   HashAlgorithm = 0
	MD5    HashAlgorithm = 1
	SHA1   HashAlgorithm = 2
	SHA224 HashAlgorithm = 3
	SHA256 HashAlgorithm = 4
	SHA384 HashAlgorithm = 5
	SHA512 HashAlgorithm = 6
)

// DigitallySigned gives information about a signature, including the algorithm used
// and the signature value.  Defined in RFC 5246 s4.7.
type DigitallySigned struct {
	Algorithm SignatureAndHashAlgorithm
	Signature []byte `tls:"minlen:0,maxlen:65535"`
}

// SerializeSCTSignatureInput serializes the passed in sct and log entry into
// the correct format for signing.
func SerializeSCTSignatureInput(sct SignedCertificateTimestamp, entry LogEntry) ([]byte, error) {
	switch sct.SCTVersion {
	case V1:
		input := CertificateTimestamp{
			SCTVersion:    sct.SCTVersion,
			SignatureType: CertificateTimestampSignatureType,
			Timestamp:     sct.Timestamp,
			EntryType:     entry.Leaf.TimestampedEntry.EntryType,
			Extensions:    sct.Extensions,
		}
		switch entry.Leaf.TimestampedEntry.EntryType {
		case X509LogEntryType:
			input.X509Entry = entry.Leaf.TimestampedEntry.X509Entry
		case PrecertLogEntryType:
			input.PrecertEntry = &PreCert{
				IssuerKeyHash:  entry.Leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
				TBSCertificate: entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate,
			}
		default:
			return nil, fmt.Errorf("unsupported entry type %s", entry.Leaf.TimestampedEntry.EntryType)
		}
		return tls.Marshal(input)
	default:
		return nil, fmt.Errorf("unknown SCT version %d", sct.SCTVersion)
	}
}


// VerifySCTSignature verifies that the SCT's signature is valid for the given LogEntry.
func (s SignatureVerifier) VerifySCTSignature(sct SignedCertificateTimestamp, entry LogEntry) error {
	sctData, err := SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		return err
	}
	return s.VerifySignature(sctData, tls.DigitallySigned(sct.Signature))
}
