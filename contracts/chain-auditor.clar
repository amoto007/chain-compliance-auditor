;; chain-auditor
;; 
;; This contract serves as the central registry for compliance audits of smart contracts 
;; on the Stacks blockchain. It allows qualified auditors to submit cryptographic attestations 
;; of a contract's compliance with various standards, regulations, and security best practices.
;; 
;; Contract owners can request audits, auditors can submit their findings with appropriate 
;; proof of work, and users can query the audit status of any registered contract.

;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-UNKNOWN-AUDITOR (err u101))
(define-constant ERR-UNKNOWN-CONTRACT (err u102))
(define-constant ERR-AUDIT-EXISTS (err u103))
(define-constant ERR-NO-AUDIT-REQUEST (err u104))
(define-constant ERR-INVALID-STANDARD (err u105))
(define-constant ERR-AUDIT-NOT-FOUND (err u106))
(define-constant ERR-NOT-CONTRACT-OWNER (err u107))
(define-constant ERR-INVALID-STATUS (err u108))

;; Status Constants
(define-constant STATUS-REQUESTED u1)
(define-constant STATUS-COMPLETED u2)
(define-constant STATUS-FAILED u3)

;; Data Structures

;; Track registered auditors
(define-map auditors principal 
  {
    name: (string-ascii 64),
    credentials: (string-ascii 128),
    registration-time: uint,
    audit-count: uint
  }
)

;; Track contract audit requests
(define-map audit-requests { contract-id: principal, standard-id: (string-ascii 64) }
  {
    owner: principal,
    request-time: uint,
    status: uint,
    description: (string-utf8 256)
  }
)

;; Store audit results
(define-map audit-results { contract-id: principal, standard-id: (string-ascii 64), auditor: principal }
  {
    timestamp: uint,
    result: bool,
    proof-hash: (buff 32),
    report-uri: (string-ascii 128),
    metadata: (string-utf8 256)
  }
)

;; Track available compliance standards
(define-map compliance-standards (string-ascii 64)
  {
    name: (string-ascii 64),
    description: (string-utf8 256),
    version: (string-ascii 32)
  }
)

;; Track contract audit history
(define-map contract-audit-history principal
  {
    audit-count: uint,
    last-audit-time: uint,
    compliant-standards: (list 20 (string-ascii 64))
  }
)

;; Contract administrator
(define-data-var contract-admin principal tx-sender)

;; Private Functions

;; Checks if caller is the contract administrator
(define-private (is-admin)
  (is-eq tx-sender (var-get contract-admin))
)

;; Checks if caller is a registered auditor
(define-private (is-auditor (auditor principal))
  (is-some (map-get? auditors auditor))
)

;; Checks if a standard exists
(define-private (standard-exists (standard-id (string-ascii 64)))
  (is-some (map-get? compliance-standards standard-id))
)

;; Update contract audit history after a successful audit
(define-private (update-audit-history (contract-id principal) (standard-id (string-ascii 64)))
  (let (
    (current-history (default-to 
      { audit-count: u0, last-audit-time: u0, compliant-standards: (list) } 
      (map-get? contract-audit-history contract-id)))
    (current-standards (get compliant-standards current-history))
    (updated-standards (if (not (is-in-list standard-id current-standards))
                          (append current-standards standard-id)
                          current-standards))
  )
  (map-set contract-audit-history contract-id
    {
      audit-count: (+ (get audit-count current-history) u1),
      last-audit-time: block-height,
      compliant-standards: updated-standards
    }
  )
  true)
)

;; Helper to check if a standard is in a list
(define-private (is-in-list (standard-id (string-ascii 64)) (standards (list 20 (string-ascii 64))))
  (is-some (index-of standards standard-id))
)

;; Public Functions

;; Set a new contract administrator
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (ok (var-set contract-admin new-admin))
  )
)

;; Register a new auditor
(define-public (register-auditor (auditor principal) (name (string-ascii 64)) (credentials (string-ascii 128)))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? auditors auditor)) ERR-AUDIT-EXISTS)
    (map-set auditors auditor
      {
        name: name,
        credentials: credentials,
        registration-time: block-height,
        audit-count: u0
      }
    )
    (ok true)
  )
)

;; Remove an auditor
(define-public (remove-auditor (auditor principal))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? auditors auditor)) ERR-UNKNOWN-AUDITOR)
    (map-delete auditors auditor)
    (ok true)
  )
)

;; Add a new compliance standard
(define-public (add-compliance-standard 
  (standard-id (string-ascii 64)) 
  (name (string-ascii 64)) 
  (description (string-utf8 256))
  (version (string-ascii 32)))
  (begin
    (asserts! (is-admin) ERR-NOT-AUTHORIZED)
    (map-set compliance-standards standard-id
      {
        name: name,
        description: description,
        version: version
      }
    )
    (ok true)
  )
)

;; Request an audit for a contract
(define-public (request-audit 
  (contract-id principal) 
  (standard-id (string-ascii 64)) 
  (description (string-utf8 256)))
  (begin
    (asserts! (standard-exists standard-id) ERR-INVALID-STANDARD)
    (asserts! (is-none (map-get? audit-requests { contract-id: contract-id, standard-id: standard-id })) 
              ERR-AUDIT-EXISTS)
    (map-set audit-requests { contract-id: contract-id, standard-id: standard-id }
      {
        owner: tx-sender,
        request-time: block-height,
        status: STATUS-REQUESTED,
        description: description
      }
    )
    (ok true)
  )
)

;; Submit audit results
(define-public (submit-audit 
  (contract-id principal) 
  (standard-id (string-ascii 64)) 
  (result bool)
  (proof-hash (buff 32))
  (report-uri (string-ascii 128))
  (metadata (string-utf8 256)))
  (let (
    (request-key { contract-id: contract-id, standard-id: standard-id })
    (result-key { contract-id: contract-id, standard-id: standard-id, auditor: tx-sender })
    (request (map-get? audit-requests request-key))
    (auditor-info (map-get? auditors tx-sender))
  )
    (asserts! (is-some request) ERR-NO-AUDIT-REQUEST)
    (asserts! (is-some auditor-info) ERR-UNKNOWN-AUDITOR)
    
    ;; Update audit request status
    (map-set audit-requests request-key
      (merge (unwrap-panic request) { status: (if result STATUS-COMPLETED STATUS-FAILED) })
    )
    
    ;; Store audit results
    (map-set audit-results result-key
      {
        timestamp: block-height,
        result: result,
        proof-hash: proof-hash,
        report-uri: report-uri,
        metadata: metadata
      }
    )
    
    ;; Update auditor stats
    (map-set auditors tx-sender
      (merge (unwrap-panic auditor-info) 
        { audit-count: (+ (get audit-count (unwrap-panic auditor-info)) u1) })
    )
    
    ;; Update contract audit history if the audit was successful
    (if result
      (update-audit-history contract-id standard-id)
      true)
    
    (ok true)
  )
)

;; Cancel an audit request (only by request owner)
(define-public (cancel-audit-request (contract-id principal) (standard-id (string-ascii 64)))
  (let (
    (request-key { contract-id: contract-id, standard-id: standard-id })
    (request (map-get? audit-requests request-key))
  )
    (asserts! (is-some request) ERR-NO-AUDIT-REQUEST)
    (asserts! (is-eq tx-sender (get owner (unwrap-panic request))) ERR-NOT-CONTRACT-OWNER)
    (map-delete audit-requests request-key)
    (ok true)
  )
)

;; Read-Only Functions

;; Get auditor information
(define-read-only (get-auditor (auditor principal))
  (map-get? auditors auditor)
)

;; Get compliance standard details
(define-read-only (get-compliance-standard (standard-id (string-ascii 64)))
  (map-get? compliance-standards standard-id)
)

;; Get audit request details
(define-read-only (get-audit-request (contract-id principal) (standard-id (string-ascii 64)))
  (map-get? audit-requests { contract-id: contract-id, standard-id: standard-id })
)

;; Get audit result details
(define-read-only (get-audit-result (contract-id principal) (standard-id (string-ascii 64)) (auditor principal))
  (map-get? audit-results { contract-id: contract-id, standard-id: standard-id, auditor: auditor })
)

;; Get contract audit history
(define-read-only (get-contract-audit-history (contract-id principal))
  (default-to 
    { audit-count: u0, last-audit-time: u0, compliant-standards: (list) } 
    (map-get? contract-audit-history contract-id)
  )
)

;; Check if a contract is compliant with a specific standard
(define-read-only (is-contract-compliant (contract-id principal) (standard-id (string-ascii 64)))
  (let (
    (history (get-contract-audit-history contract-id))
    (standards (get compliant-standards history))
  )
    (is-in-list standard-id standards)
  )
)

;; Get the current contract administrator
(define-read-only (get-admin)
  (var-get contract-admin)
)