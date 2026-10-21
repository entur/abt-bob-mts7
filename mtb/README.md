# mtb
Mobile Ticket Bundle (MTB) as defined in MTS1: data structures, parser and writer.

Has no dependencies on the other artifacts, so it can be used by issuers as well as by readers. The parser is permissive, while the writer
produces definite length CBOR, so that the encoded MTB is stable byte for byte.
